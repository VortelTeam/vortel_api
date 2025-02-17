import json


def lambda_handler(event, context):
    print("Hello from lambda")
    return {"statusCode": 200, "body": json.dumps("Hello from Lambda!")}
