# AWS S3 Customer-Provided Encryption Key Scanner

This repository contains two scripts for scanning AWS S3 buckets across multiple accounts to identify buckets using customer-provided encryption keys (SSE-C). There's a sequential version and a parallel version for handling large numbers of accounts efficiently.

## Prerequisites

- Python 3.7+
- AWS credentials configured
- Required Python packages:
  ```bash
  pip install boto3
  ```

- IAM roles in each target account with the following permissions:
  ```json
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "s3:ListBuckets",
                  "s3:GetBucketEncryption"
              ],
              "Resource": "*"
          }
      ]
  }
  ```

## Scripts Overview

### 1. Sequential Script (`sequential_scanner.py`)
Best for scanning a small number of accounts (< 50). Processes accounts and buckets one at a time.

### 2. Parallel Script (`parallel_scanner.py`)
Optimized for scanning large numbers of accounts (50+). Processes multiple accounts and buckets concurrently.

## Configuration

Both scripts require a list of AWS accounts to scan. The accounts are configured in the `main()` function of each script.

### Sequential Script Configuration
```python
accounts = [
    {
        'id': '123456789012',
        'role_arn': 'arn:aws:iam::123456789012:role/CrossAccountRole'
    },
    # Add more accounts as needed
]
```

### Parallel Script Configuration
```python
accounts = [
    Account(id='123456789012', role_arn='arn:aws:iam::123456789012:role/CrossAccountRole'),
    # Add more accounts as needed
]
```

## Usage

### Sequential Script
```bash
python sequential_scanner.py
```

### Parallel Script
```bash
python parallel_scanner.py
```

## Performance Tuning (Parallel Script)

The parallel script has two configurable parameters for controlling concurrent operations:

1. Account-level parallelization:
```python
ThreadPoolExecutor(max_workers=20)  # In main()
```

2. Bucket-level parallelization:
```python
ThreadPoolExecutor(max_workers=10)  # In check_account()
```

Adjust these values based on:
- Your system's resources
- AWS API rate limits
- Network conditions

## Output Format

Both scripts provide similar output:

```
Buckets using SSE-C:
Account: 123456789012, Bucket: bucket-name-1
Account: 234567890123, Bucket: bucket-name-2
```

The parallel script also provides additional statistics:
```
Total time taken: HH:MM:SS
Total accounts processed: X
Total buckets with SSE-C found: Y
Total errors encountered: Z
```

## Error Handling

### Sequential Script
- Basic error handling with error messages printed to console
- Continues to next bucket/account on error

### Parallel Script
- Enhanced error handling with logging
- Detailed error reporting per bucket
- Summary statistics including error count
- Concurrent operation management

## Common Issues and Troubleshooting

1. **AWS Credentials**
   - Ensure AWS credentials are properly configured
   - Verify role ARNs are correct
   - Check permissions in target accounts

2. **Rate Limiting**
   - If hitting AWS API limits, reduce `max_workers`
   - Add delays between API calls if needed

3. **Memory Usage**
   - For large numbers of accounts/buckets, monitor memory usage
   - Adjust parallel processing parameters if needed

## Best Practices

1. **Testing**
   - Start with a small number of accounts
   - Validate results before running on all accounts
   - Use sequential script for testing/debugging

2. **Production Use**
   - Use parallel script for large account sets
   - Implement appropriate error handling
   - Monitor AWS service quotas

3. **Security**
   - Use least-privilege IAM roles
   - Regularly rotate credentials
   - Monitor and audit script activity

## Limitations

- Requires appropriate IAM roles in all target accounts
- Subject to AWS API rate limits
- Memory usage scales with concurrency settings

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT
