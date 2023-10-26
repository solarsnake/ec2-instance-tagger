# EC2 Instance Tagger Lambda Deployment

This script sets up an AWS Lambda function that tags EC2 instances based on their OS type when they are launched. It uses a CloudWatch Event rule to trigger the Lambda function whenever an EC2 instance enters a "pending" state. This deployment script also ensures the required IAM role and policies are in place for the Lambda function.

## Requirements

- Python 3.7 or newer
- Boto3 and Botocore Python libraries (install using `pip install -r requirements.txt`)
- AWS CLI configured with necessary profiles (this script specifically looks for profiles within the ~/.aws/credentials file)
- An existing AWS Lambda function file named `lambda_tagger.py` in the same directory

## Usage

## Deployment

To deploy the Lambda function and associated resources for every valid profile in ~/.aws/credentials, simply run:

```bash
python deploy.py
```

This will:

- Create an IAM role (am-lambda-tagger-role) with the necessary permissions.
- Deploy the Lambda function (EC2Tagger) that will handle the EC2 instance tagging.
- Set up a CloudWatch Events rule (EC2LaunchRule) to trigger the Lambda function whenever an EC2 instance is launched.

## Reversion

To remove the resources created by this script for every valid profile:

```bash
python deploy.py --revert

```

This will:

- Delete the Lambda function.
- Remove the CloudWatch Events rule.
- Delete the IAM role and associated policies.

## Notes

Always ensure that your AWS credentials have the necessary permissions to create and delete IAM roles, Lambda functions, and CloudWatch Events.
Before running the revert option, confirm that you are okay with deleting the resources as the changes are irreversible.
Regularly check for AWS updates regarding the Lambda runtimes and IAM permissions to ensure compatibility.
