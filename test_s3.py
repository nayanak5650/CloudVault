import os
import boto3
from dotenv import load_dotenv

load_dotenv()

bucket_name = os.getenv("AWS_S3_BUCKET")
region = os.getenv("AWS_REGION")

s3 = boto3.client("s3", region_name=region)

try:
    s3.head_bucket(Bucket=bucket_name)
    print("Success! CloudVault is connected to AWS S3.")
    print("Bucket:", bucket_name)
except Exception as e:
    print("S3 connection failed.")
    print("Error:", e)
