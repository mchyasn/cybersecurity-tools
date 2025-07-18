# CloudMisconfigHunter – Detection Logic Overview

## AWS Checks
- Public S3 bucket ACL scan using boto3
- IAM user enumeration with alert on high volume

## GCP Checks
- HTTP GET test against public Google Storage bucket
- Basic open endpoint detection via unauthenticated API call

## Azure Checks
- Blob container access check via public URL
- Azure WebApp open API test via HTTP

## Alert Output
- Alerts written to logs/alerts.txt in timestamped format
- Format: [CLOUD][UTC ISO TS] Message

## Notes
- Requires valid cloud credentials for AWS checks
- GCP/Azure simulated with unauthenticated GETs for now
