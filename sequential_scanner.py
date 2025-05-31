import boto3
from botocore.exceptions import ClientError

def check_bucket_encryption(account, bucket_name, role_arn):
    """Check encryption settings for a specific bucket"""
    try:
        # Assume role in target account
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='CheckEncryption'
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
                        return True
            return False
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return False
            raise e
            
    except Exception as e:
        print(f"Error checking bucket {bucket_name} in account {account}: {str(e)}")
        return False

def main():
    # List of accounts to check
    accounts = [
        {
            'id': '123456789012',
            'role_arn': 'arn:aws:iam::123456789012:role/CrossAccountRole'
        }
        # Add more accounts as needed
    ]
    
    results = []
    
    for account in accounts:
        try:
            # Assume role and list buckets
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=account['role_arn'],
                RoleSessionName='ListBuckets'
            )
            
            s3_client = boto3.client(
                's3',
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
            
            # List all buckets in account
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                if check_bucket_encryption(account['id'], bucket['Name'], account['role_arn']):
                    results.append({
                        'account_id': account['id'],
                        'bucket_name': bucket['Name']
                    })
                    
        except Exception as e:
            print(f"Error processing account {account['id']}: {str(e)}")
    
    # Print results
    print("\nBuckets using SSE-C:")
    for result in results:
        print(f"Account: {result['account_id']}, Bucket: {result['bucket_name']}")

if __name__ == "__main__":
    main()
