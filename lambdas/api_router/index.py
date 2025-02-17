import base64
import os
import simplejson as json
import uuid
from typing import Dict, Any, List
import time
import boto3
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, Response
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.logging import correlation_paths
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools.event_handler.exceptions import (
    BadRequestError,
    NotFoundError,
    ServiceError,
    UnauthorizedError,
)
import hashlib

logger = Logger()
tracer = Tracer()
metrics = Metrics()
app = APIGatewayRestResolver()

s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
metadata_table = dynamodb.Table(os.environ["METADATA_TABLE"])
job_table = dynamodb.Table(os.environ["INFERENCE_JOBS_TABLE"])
sqs_client = boto3.client("sqs")
INPUT_BUCKET_NAME = os.environ["INPUT_BUCKET_NAME"]
OUTPUT_BUCKET_NAME = os.environ["OUTPUT_BUCKET_NAME"]
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET, DELETE",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
}


@app.get("/files")
@tracer.capture_method
def list_files():
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        response = metadata_table.query(
            KeyConditionExpression="user_id = :uid",
            ExpressionAttributeValues={":uid": user_id},
        )
        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(response["Items"]),
        )
    except ClientError as e:
        logger.exception("Failed to list files")
        raise ServiceError(msg="Failed to retrieve files")


@app.post("/files")
@tracer.capture_method
def upload_file():
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    if app.current_event.is_base64_encoded:
        # Decode base64 and then decode bytes to string
        file_content = base64.b64decode(app.current_event.body).decode("utf-8")
    else:
        file_content = app.current_event.body

    # Check file size
    if len(file_content) > MAX_FILE_SIZE:
        raise BadRequestError(f"File too large. Maximum size is {MAX_FILE_SIZE} bytes")

    content_type = app.current_event.headers.get(
        "content-type", "application/octet-stream"
    )
    filename = app.current_event.headers.get("filename", "unnamed-file")

    # Generate file_id as the hash of the filename
    file_id = hashlib.sha256(filename.encode()).hexdigest()[0:8]
    key = f"{user_id}/{file_id}"

    try:
        # Upload to S3
        s3_client.put_object(
            Bucket=INPUT_BUCKET_NAME,
            Key=key,
            Body=file_content,
            ContentType=content_type,
        )

        # Prepare metadata
        metadata = {
            "user_id": user_id,
            "file_id": file_id,
            "filename": filename,
            "content_type": content_type,
            "size": len(file_content),
            "last_modified": int(time.time()),
        }

        # Upsert in DynamoDB
        metadata_table.put_item(
            Item=metadata,
        )

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(metadata),
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"AWS error during upload: {error_code}")
        if error_code == "NoSuchBucket":
            raise NotFoundError("Storage bucket not found")
        raise ServiceError(msg="Failed to upload file")


@app.delete("/files/<file_id>")
@tracer.capture_method
def delete_file(file_id: str):
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        # First, retrieve the metadata to get the S3 key
        response = metadata_table.get_item(Key={"user_id": user_id, "file_id": file_id})

        if "Item" not in response:
            raise NotFoundError("File not found")

        # Delete from S3
        s3_client.delete_object(Bucket=INPUT_BUCKET_NAME, Key=f"{user_id}/{file_id}")

        # Delete metadata
        metadata_table.delete_item(Key={"user_id": user_id, "file_id": file_id})

        return Response(status_code=204, headers=CORS_HEADERS)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"AWS error during deletion: {error_code}")
        if error_code == "ResourceNotFoundException":
            raise NotFoundError("File metadata not found")
        raise ServiceError(msg="Failed to delete file")


def retrieve_files(user_id: str, file_list: List[str]) -> List[Dict[str, Any]]:
    logger.debug(f"Retrieving files: {file_list}")
    files = []
    for file_id in file_list:
        try:
            response = metadata_table.get_item(
                Key={"user_id": user_id, "file_id": file_id}
            )
            if "Item" in response:
                files.append(response["Item"])
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving file {file_id}: {error_code}")
            if error_code == "ResourceNotFoundException":
                continue
            raise ServiceError(msg=f"Failed to retrieve file {file_id}")
    return files


@app.post("/jobs")
@tracer.capture_method
def create_batch_inference_job():
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    job_id = str(uuid.uuid4())

    # Validate request body
    if not app.current_event.body:
        raise BadRequestError("Request body is required")

    body = app.current_event.json_body

    try:
        file_list = body.get("files")
    except json.JSONDecodeError:
        raise BadRequestError("Invalid JSON format in request body")

    if not isinstance(file_list, list):
        raise BadRequestError("Request body must be a list of file IDs")

    if not file_list:
        raise BadRequestError("File list cannot be empty")

    # Retrieve files
    files = retrieve_files(user_id, file_list)
    if not files:
        raise NotFoundError("None of the specified files were found")

    # Validate prompt
    prompt = body.get("prompt")
    if not prompt:
        raise BadRequestError("Prompt is required")

    # Send SQS message
    try:
        message_body = {
            "user_id": user_id,
            "job_id": job_id,
            "job_status": "PENDING",
            "input_files": files,
            "prompt": prompt,
        }

        sqs_client.send_message(
            QueueUrl=os.environ["INFERENCE_QUEUE_URL"],
            MessageBody=json.dumps(message_body),
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"SQS error: {error_code}")
        if error_code == "QueueDoesNotExist":
            raise NotFoundError("Job queue not available")
        elif error_code == "InvalidMessageContents":
            raise BadRequestError("Invalid message format")
        raise ServiceError(msg="Failed to queue job")

    # Write job to DynamoDB
    try:
        current_time = int(time.time())
        job_table.put_item(
            Item={
                "user_id": user_id,
                "job_id": job_id,
                "job_status": "PENDING",
                "prompt": prompt,
                "input_files": files,
                "created_at": current_time,
                "updated_at": current_time,
                "job_error": "",
            }
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"DynamoDB error while creating job: {e}")
        if error_code == "ResourceNotFoundException":
            raise NotFoundError("Jobs table not found")
        elif error_code == "ProvisionedThroughputExceededException":
            raise ServiceError(
                msg="Service is currently overloaded, please try again later"
            )
        raise ServiceError(msg="Failed to create job record")

    return Response(
        status_code=201,
        headers=CORS_HEADERS,
        body=json.dumps(
            {
                "job_id": job_id,
                "status": "PENDING",
                "prompt": prompt,
                "created_at": current_time,
                "input_files": files,
            }
        ),
    )


@app.get("/jobs")
@tracer.capture_method
def list_jobs():
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        # Retrieve all jobs for the user
        response = job_table.query(KeyConditionExpression=Key("user_id").eq(user_id))

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps([item for item in response["Items"]]),
        )
    except ClientError as e:
        logger.exception("Failed to list jobs")
        raise ServiceError(msg="Failed to retrieve jobs")


@app.get("/jobs/<job_id>/download/<file_id>")
@tracer.capture_method
def get_download_url(job_id: str, file_id: str):
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        # Retrieve the job record from DynamoDB
        job_response = job_table.get_item(Key={"user_id": user_id, "job_id": job_id})
        if "Item" not in job_response:
            raise NotFoundError(f"Job {job_id} not found")

        # Check if the file is part of the job
        file_found = False
        for file in job_response["Item"]["input_files"]:
            if file["file_id"] == file_id:
                file_found = True
                break
        if not file_found:
            raise NotFoundError(f"File {file_id} not found in job {job_id}")

        # Generate a presigned URL for the file
        # TODO: make sure to sync with the inference output key
        s3_key = f"{user_id}/{job_id}/{file_id}_result.txt"
        presigned_url = s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": OUTPUT_BUCKET_NAME, "Key": s3_key},
            ExpiresIn=600,
        )

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps({"presigned_url": presigned_url}),
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"AWS error during download URL generation: {error_code}")
        if error_code == "NoSuchKey":
            raise NotFoundError(f"File {file_id} not found")
        raise ServiceError(msg="Failed to generate download URL")
    except Exception as e:
        logger.exception(
            f"Error generating download URL for file {file_id} in job {job_id}"
        )
        raise ServiceError(msg="Failed to generate download URL")


@logger.inject_lambda_context(
    correlation_id_path=correlation_paths.API_GATEWAY_REST, log_event=True
)
@tracer.capture_lambda_handler
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    try:
        return app.resolve(event, context)
    except (BadRequestError, NotFoundError, UnauthorizedError, ServiceError) as e:
        logger.exception(str(e))
        return {"statusCode": e.status_code, "body": json.dumps({"message": str(e)})}
    except Exception as e:
        logger.exception("Unknown error occurred")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Internal server error"}),
        }
