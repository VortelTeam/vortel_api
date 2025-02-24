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
MAX_FILES_PER_JOB = 50  # New cost control parameter
MAX_FILES_PER_LIST = 100  # Max files per list operation

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET,DELETE",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
}


def _truncate_metadata(metadata: Dict[str, str]) -> Dict[str, str]:
    """Truncate metadata to only include essential fields."""
    return {
        "filename": metadata.get("filename", ""),
        "content_type": metadata.get("content-type", ""),
    }


@app.get("/files")
@tracer.capture_method
def list_files():
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        # Get pagination parameters from query string
        page_size = min(
            int(app.current_event.get_query_string_value("limit", "100")),
            MAX_FILES_PER_LIST,
        )
        continuation_token = app.current_event.get_query_string_value(
            "continuationToken"
        )

        # List objects with pagination
        list_args = {
            "Bucket": INPUT_BUCKET_NAME,
            "Prefix": f"{user_id}/",
            "MaxKeys": page_size,
        }
        if continuation_token:
            list_args["ContinuationToken"] = continuation_token

        response = s3_client.list_objects_v2(**list_args)

        files = []
        if "Contents" not in response:
            return Response(
                status_code=200,
                headers=CORS_HEADERS,
                body=json.dumps(
                    {
                        "files": [],
                        "continuationToken": response.get("NextContinuationToken"),
                    }
                ),
            )

        for obj in response["Contents"]:
            key = obj["Key"]
            if key == f"{user_id}/":
                continue

            try:
                # Get object metadata from S3
                head_response = s3_client.head_object(Bucket=INPUT_BUCKET_NAME, Key=key)
                metadata = _truncate_metadata(head_response.get("Metadata", {}))

                files.append(
                    {
                        "file_id": key.split("/")[1],
                        "filename": metadata.get("filename"),
                        "content_type": head_response.get("ContentType", ""),
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )
            except ClientError as e:
                logger.error(f"Failed to retrieve metadata for {key}: {str(e)}")

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(
                {
                    "files": files,
                    "continuationToken": response.get("NextContinuationToken"),
                }
            ),
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
        all_metadata = _truncate_metadata({**server_metadata, **client_metadata})

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

    # Validate request body
    body = app.current_event.json_body
    file_list = body.get("files", [])

    if len(file_list) > MAX_FILES_PER_JOB:
        raise BadRequestError(f"Exceeded maximum of {MAX_FILES_PER_JOB} files per job")

    # Retrieve and validate files
    valid_files = []
    for file_id in file_list[:MAX_FILES_PER_JOB]:  # Enforce max files
        s3_key = f"{user_id}/{file_id}"
        try:
            head_response = s3_client.head_object(Bucket=INPUT_BUCKET_NAME, Key=s3_key)
            metadata = _truncate_metadata(head_response.get("Metadata", {}))
            valid_files.append(
                {
                    "file_id": file_id,
                    "filename": metadata.get("filename"),
                }
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "404":
                logger.error(f"Error retrieving file {file_id}: {str(e)}")

    if not valid_files:
        raise NotFoundError("No valid files found")

    # Create job record
    job_id = str(uuid.uuid4())
    current_time = int(time.time())
    dynamo_item = {
        "user_id": user_id,
        "job_id": job_id,
        "job_status": "PENDING",
        "file_ids": [f["file_id"] for f in valid_files],
        "created_at": current_time,
        "updated_at": current_time,
        "job_error": "",
    }

    try:
        # First write to DynamoDB to ensure we have a record before queueing
        job_table.put_item(Item=dynamo_item)
    except ClientError as e:
        logger.error(f"DynamoDB error while creating job: {e}")
        raise ServiceError(msg="Failed to create job record")

    try:
        # Send minimal data to SQS to reduce message size
        sqs_client.send_message(
            QueueUrl=os.environ["JOBS_QUEUE_URL"],
            MessageBody=json.dumps(
                {
                    "user_id": user_id,
                    "job_id": job_id,
                    "action": "process_job",  # Added for clearer message purpose
                    "file_ids": [f["file_id"] for f in valid_files],
                }
            ),
            MessageAttributes={
                "JobType": {"StringValue": "data_extraction", "DataType": "String"}
            },
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"SQS send error: {error_code}")

        # Attempt to clean up failed job record
        try:
            job_table.delete_item(Key={"user_id": user_id, "job_id": job_id})
        except ClientError as delete_error:
            logger.error(f"Failed to clean up job {job_id}: {delete_error}")

        if error_code == "QueueDoesNotExist":
            raise NotFoundError("Job queue not available")
        raise ServiceError(msg="Failed to queue job")

    return Response(
        status_code=201,
        headers=CORS_HEADERS,
        body=json.dumps(
            {
                "job_id": job_id,
                "status": "PENDING",
                "created_at": current_time,
                "file_count": len(valid_files),
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
        # Add pagination support
        limit = min(int(app.current_event.get_query_string_value("limit", "100")), 100)
        exclusive_start_key = json.loads(
            app.current_event.get_query_string_value("exclusiveStartKey", "null")
        )

        query_args = {
            "KeyConditionExpression": Key("user_id").eq(user_id),
            "Limit": limit,
            "ProjectionExpression": "job_id, job_status, created_at, automation_job_arns",  # Only essential fields
        }
        if exclusive_start_key:
            query_args["ExclusiveStartKey"] = exclusive_start_key

        response = job_table.query(**query_args)

        return Response(
            status_code=200,
            headers=CORS_HEADERS,
            body=json.dumps(
                {
                    "jobs": response["Items"],
                    "lastEvaluatedKey": response.get("LastEvaluatedKey"),
                }
            ),
        )
    except ClientError as e:
        logger.exception("Failed to list jobs")
        raise ServiceError(msg="Failed to retrieve jobs")


@app.get("/jobs/<job_id>/download")
@tracer.capture_method
def get_download_url(job_id: str):
    user_id = app.current_event.request_context.authorizer.claims.get("sub")
    if not user_id:
        raise UnauthorizedError("User ID not found in claims")

    try:
        # Retrieve minimal job data
        job_response_arns = job_table.get_item(
            Key={"user_id": user_id, "job_id": job_id},
            ProjectionExpression="automation_job_arns",
        )
        if "Item" not in job_response_arns:
            raise NotFoundError(f"Job {job_id} not found")

        # Extract extraction id from automation job ARN
        automation_job_arns = job_response_arns["Item"].get("automation_job_arns", [])
        first_ar = automation_job_arns[0]
        extraction_id = first_ar.split("/")[-1]

        # Generate a presigned URL for the file
        s3_key = f"/{extraction_id}/0/custom_output/0/result.json"
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
            raise NotFoundError(f"Extraction result for {job_id} not found")
        raise ServiceError(msg="Failed to generate download URL")
    except Exception as e:
        logger.exception(f"Error generating result download URL for job {job_id}")
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
