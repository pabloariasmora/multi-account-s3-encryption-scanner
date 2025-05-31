import boto3
from botocore.exceptions import ClientError
import concurrent.futures
from typing import Dict, List
import logging
from dataclasses import dataclass
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Account:
    id: str
    role_arn: str

@dataclass
class BucketResult:
    account_id: str
    bucket_name: str
    error: str = None

def check_single_bucket(account: Account, bucket_name: str) -> BucketResult:
    """Check encryption settings for a single bucket"""
    try:
        # Assume role in target account
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=account.role_arn,
            RoleSessionName=f'CheckEncryption-{datetime.now().timestamp()}'
        )
        
        # Create S3 client with temporary credentials
        s3_client = boto3.client(
            's3',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        
        # Get bucket encryption configuration
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption['ServerSideEncryptionConfiguration']['Rules']
            
            # Check for SSE-C
            for rule in rules:
                if 'ApplyServerSideEncryptionByDefault' in rule:
                    if rule['ApplyServerSideEncryptionByDefault'].get('SSEAlgorithm') == 'AES256':
                        return BucketResult(account.id, bucket_name)
            return None
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return None
            return BucketResult(account.id, bucket_name, str(e))
            
    except Exception as e:
        return BucketResult(account.id, bucket_name, str(e))

def check_account(account: Account) -> List[BucketResult]:
    """Check all buckets in an account"""
    results = []
    try:
        # Assume role and list buckets
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=account.role_arn,
            RoleSessionName=f'ListBuckets-{datetime.now().timestamp()}'
        )
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        
        # List all buckets in account
        buckets = s3_client.list_buckets()['Buckets']
        
        # Create a thread pool for checking buckets within this account
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {
                executor.submit(check_single_bucket, account, bucket['Name']): bucket['Name']
                for bucket in buckets
            }
            
            for future in concurrent.futures.as_completed(future_to_bucket):
                result = future.result()
                if result:
                    results.append(result)
                    
    except Exception as e:
        logger.error(f"Error processing account {account.id}: {str(e)}")
        
    return results

def main():
    # List of accounts to check
    accounts = [
        Account(id='123456789012', role_arn='arn:aws:iam::123456789012:role/CrossAccountRole'),
        # Add more accounts here
    ]
    
    results = []
    start_time = datetime.now()
    
    # Process accounts in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_account = {executor.submit(check_account, account): account for account in accounts}
        
        for future in concurrent.futures.as_completed(future_to_account):
            account = future_to_account[future]
            try:
                account_results = future.result()
                results.extend(account_results)
            except Exception as e:
                logger.error(f"Account {account.id} generated an exception: {str(e)}")
    
    end_time = datetime.now()
    
    # Print results
    print("\nBuckets using SSE-C:")
    for result in results:
        if result.error:
            print(f"Account: {result.account_id}, Bucket: {result.bucket_name}, Error: {result.error}")
        else:
            print(f"Account: {result.account_id}, Bucket: {result.bucket_name}")
    
    print(f"\nTotal time taken: {end_time - start_time}")
    print(f"Total accounts processed: {len(accounts)}")
    print(f"Total buckets with SSE-C found: {len([r for r in results if not r.error])}")
    print(f"Total errors encountered: {len([r for r in results if r.error])}")

if __name__ == "__main__":
    main()
