import os
from typing import Dict, Any

import boto3
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.data_classes import SQSEvent
from aws_lambda_powertools.utilities.batch import (
    BatchProcessor,
    EventType,
    process_partial_response,
)

logger = Logger()
tracer = Tracer()
metrics = Metrics()
processor = BatchProcessor(event_type=EventType.SQS)

da_client = boto3.client("bedrock-data-automation-runtime")
USER_FILES_BUCKET = os.environ.get("USER_FILES_BUCKET")
BLUEPRINT_ARN = "arn:aws:bedrock:us-west-2:668618083225:blueprint/07482b6cbaf4"
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET")


@tracer.capture_method
def record_handler(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process individual SQS record
    """
    try:
        # Extract information from the record
        message_body = record["body"]
        user_id = message_body["user_id"]
        input_file = message_body["input_files"][0]
        file_id = input_file["file_id"]

        # Construct S3 URI
        input_s3_uri = f"s3://{USER_FILES_BUCKET}/{user_id}/{file_id}"
        output_s3_uri = f"s3://{OUTPUT_BUCKET}"

        logger.info(
            "Invoking Bedrock Data Automation",
            extra={"input_uri": input_s3_uri, "user_id": user_id, "file_id": file_id},
        )

        # Call Bedrock Data Automation
        response = da_client.invoke_data_automation_async(
            inputConfiguration={
                "s3Uri": input_s3_uri,
            },
            outputConfiguration={
                "s3Uri": output_s3_uri,
            },
            blueprints=[
                {
                    "blueprintArn": BLUEPRINT_ARN,
                },
            ],
        )

        metrics.add_metric(name="SuccessfulInvocations", unit=MetricUnit.Count, value=1)
        return response

    except Exception as e:
        logger.exception("Error processing record")
        metrics.add_metric(name="FailedInvocations", unit=MetricUnit.Count, value=1)
        raise


@logger.inject_lambda_context
@tracer.capture_lambda_handler
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda handler for processing SQS events
    """
    try:
        # Parse SQS event
        event = SQSEvent(event)

        # Process batch
        return process_partial_response(
            event=event,
            record_handler=record_handler,
            processor=processor,
            context=context,
        )
    except Exception as e:
        logger.exception("Error in lambda handler")
        raise
