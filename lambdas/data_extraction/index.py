import json
import boto3

da_client = boto3.client("bedrock-data-automation-runtime")

def call_da():
    response = da_client.invoke_data_automation_async(
        inputConfiguration={},
        outputConfiguration={},
    )

def lambda_handler(event, context):
    
