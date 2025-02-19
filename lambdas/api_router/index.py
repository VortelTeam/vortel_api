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
job_table = dynamodb.Table(os.environ["JOBS_TABLE"])
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
        # List all objects for the user
        response = s3_client.list_objects_v2(
            Bucket=INPUT_BUCKET_NAME, Prefix=f"{user_id}/"
        )

        files = []
        if "Contents" not in response:
            return Response(
                status_code=200,
                headers=CORS_HEADERS,
                body=json.dumps([]),
            )

        for obj in response["Contents"]:
            key = obj["Key"]
            # Skip directory-like entries
            if key == f"{user_id}/":
                continue

            try:
                # Get object metadata
                head_response = s3_client.head_object(Bucket=INPUT_BUCKET_NAME, Key=key)
                metadata = head_response["Metadata"]

                # Process metadata
                file_metadata = {}
                for k, v in metadata.items():
                    if k.startswith("x-amz-meta-"):
                        file_metadata[k[11:]] = v
                    else:
                        file_metadata[k] = v

                files.append(
                    {
                        "file_id": key.split("/")[1],
                        "filename": file_metadata.get("filename"),
                        "content_type": head_response.get("ContentType", ""),
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                        "metadata": file_metadata,
                    }
                )
            except ClientError as e:
                logger.error(f"Failed to retrieve metadata for {key}: {str(e)}")

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(files),
        )
    except ClientError as e:
        logger.exception("Failed to list files from S3")
        raise ServiceError(msg="Failed to retrieve files")


@app.post("/upload-url")
@tracer.capture_method
def create_upload_url():
    """Generate a pre-signed URL for S3 file upload with metadata"""
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    # Parse request body
    try:
        body = app.current_event.json_body
        filename = body.get("fileName")
        if "/" in filename:
            raise BadRequestError("Invalid filename")
        content_type = body.get("contentType")
        client_metadata = body.get("metadata", {})
    except json.JSONDecodeError:
        raise BadRequestError("Invalid JSON format")

    if not filename or not content_type:
        raise BadRequestError("fileName and contentType are required")

    # Generate file ID
    file_id = hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()[:8]
    s3_key = f"{user_id}/{file_id}"

    try:
        # Create server-generated metadata
        server_metadata = {
            "user-id": user_id,
            "file-id": file_id,
            "filename": filename,
            "created-at": str(int(time.time())),
        }

        # Combine with client metadata
        all_metadata = {**server_metadata, **client_metadata}

        # Prepare S3 upload fields and conditions
        fields = {"content-type": content_type}
        conditions = [
            {"bucket": INPUT_BUCKET_NAME},
            ["content-length-range", 0, MAX_FILE_SIZE],
            {"key": s3_key},
            {"content-type": content_type},
        ]

        # Add metadata fields
        for key, value in all_metadata.items():
            meta_key = f"x-amz-meta-{key}"
            fields[meta_key] = value
            conditions.append({meta_key: value})

        # Generate pre-signed POST
        presigned_post = s3_client.generate_presigned_post(
            Bucket=INPUT_BUCKET_NAME,
            Key=s3_key,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=3600,
        )

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(
                {
                    "uploadUrl": presigned_post["url"],
                    "fields": presigned_post["fields"],
                    "fileId": file_id,
                }
            ),
        )
    except ClientError as e:
        logger.exception("Failed to generate presigned URL")
        raise ServiceError("Failed to create upload URL")


@app.delete("/files/<file_id>")
@tracer.capture_method
def delete_file(file_id: str):
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    s3_key = f"{user_id}/{file_id}"

    try:
        # Verify file exists
        s3_client.head_object(Bucket=INPUT_BUCKET_NAME, Key=s3_key)
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            raise NotFoundError("File not found")
        raise ServiceError("Error verifying file existence")

    try:
        s3_client.delete_object(Bucket=INPUT_BUCKET_NAME, Key=s3_key)
        return Response(status_code=204, headers=CORS_HEADERS)
    except ClientError as e:
        logger.exception("Failed to delete file from S3")
        raise ServiceError("Failed to delete file")


def retrieve_files(user_id: str, file_list: List[str]) -> List[Dict[str, Any]]:
    files = []
    for file_id in file_list:
        s3_key = f"{user_id}/{file_id}"
        try:
            head_response = s3_client.head_object(Bucket=INPUT_BUCKET_NAME, Key=s3_key)
            metadata = head_response["Metadata"]

            file_metadata = {}
            for k, v in metadata.items():
                if k.startswith("x-amz-meta-"):
                    file_metadata[k[11:]] = v
                else:
                    file_metadata[k] = v

            files.append(
                {
                    "file_id": file_id,
                    "filename": file_metadata.get("filename"),
                    "content_type": head_response.get("ContentType", ""),
                    "metadata": file_metadata,
                }
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                continue
            logger.error(f"Error retrieving file {file_id}: {str(e)}")
    return files


@app.post("/jobs")
@tracer.capture_method
def create_data_extraction_job():
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

    # Send SQS message
    try:
        message_body = {
            "user_id": user_id,
            "job_id": job_id,
            "job_status": "PENDING",
            "input_files": files,
        }

        sqs_client.send_message(
            QueueUrl=os.environ["JOBS_QUEUE_URL"],
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
        return {
            "statusCode": e.status_code,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": str(e)}),
        }
    except Exception as e:
        logger.exception("Internal server error")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "Internal server error"}),
        }
