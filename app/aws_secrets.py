import boto3 
import json 




def get_aws_secret(secret_name, region="us-east-2"):

    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])
