import argparse
import boto3
from botocore.exceptions import ClientError
import json
import os
import re
import time
import zipfile

# Modify these to fit your environment
rule_name = "EC2LaunchRule"
role_name = "Ec2LambdaTaggerRole"
lambda_function_name = "EC2Tagger"

# To remove all created resources pass --revert to the script
parser = argparse.ArgumentParser(description='Deploy or Revert Lambda Resources')
parser.add_argument('--revert', action='store_true', help='Revert or delete created resources')
args = parser.parse_args()

def revert_resources(profile_name):
    session = boto3.Session(profile_name=profile_name)
    lambda_client = session.client('lambda')
    events_client = session.client('events')
    iam_client = session.client('iam')

    try:
        lambda_client.delete_function(FunctionName=lambda_function_name)
        print(f"Deleted Lambda function {lambda_function_name} for profile {profile_name}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Lambda function {lambda_function_name} not found for profile {profile_name}. Skipping deletion.")
        else:
            print(f"Error deleting Lambda function for profile {profile_name}: {e}")

    try:
        events_client.remove_targets(
            Rule=rule_name,
            Ids=['ec2StartupTrigger']
        )
        events_client.delete_rule(Name=rule_name)
        print(f"Deleted CloudWatch Events rule {rule_name} for profile {profile_name}")
    except ClientError as e:
        print(f"Error deleting CloudWatch Events rule for profile {profile_name}: {e}")

    try:
        for policy in iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
        
        for policy in iam_client.list_role_policies(RoleName=role_name)['PolicyNames']:
            iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy)
        
        iam_client.delete_role(RoleName=role_name)
        print(f"Deleted IAM role {role_name} for profile {profile_name}")
    except ClientError as e:
        print(f"Error deleting IAM role or its policies for profile {profile_name}: {e}")

aws_credentials_file = os.path.expanduser("~/.aws/credentials")
profiles = []

if os.path.exists(aws_credentials_file):
    with open(aws_credentials_file, 'r') as f:
        contents = f.read()
        profiles = re.findall(r'\[(.*?)\]', contents)

valid_profiles = []
for profile_name in profiles:
    try:
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        sts_client.get_caller_identity()
        iam_client = session.client('iam')
        lambda_client = session.client('lambda')
        valid_profiles.append(profile_name)
    except:
        print(f"Profile '{profile_name}' has invalid credentials.")

if args.revert:
    for profile_name in valid_profiles:
        revert_resources(profile_name)
else:
    for profile_name in valid_profiles:
        session = boto3.Session(profile_name=profile_name)
        region = session.region_name
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()["Account"]

        iam_client = session.client('iam')
        # Modify this for public cloud if needed
        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:CreateTags"
                ],
                "Resource": "*"
            }, {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": f"arn:aws:logs:{region}:{account_id}:*"
            }]
        })

        assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }]
        })

        def create_role(iam_client, role_name, assume_role_policy_document, permissions_boundary_arn, policy_json):
            try:
                response = iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=assume_role_policy_document,
                    Description="Role for Lambda to tag EC2 instances based on OS type",
                    PermissionsBoundary=permissions_boundary_arn
                )
                try:
                    iam_client.put_role_policy(
                        RoleName=role_name,
                        PolicyName="Ec2LambdaTaggerPolicy",
                        PolicyDocument=policy_json
                    )
                except ClientError as e:
                    print(f"Failed to attach policy to role '{role_name}' for profile {profile_name}. Error: {e}")
                return response['Role']['Arn']
            except Exception as e:
                print(f"Failed to create role '{role_name}'. Error: {str(e)}")
                return None

        role_arn = None
        roles = [role for role in iam_client.list_roles()['Roles'] if role['RoleName'] == role_name]
        # if you want to add a permission boundary, add Your_Policy_Name below
        permissions_boundary_arn = "arn:aws:iam::{}:policy/Your_Policy_Name".format(account_id)

        if not roles:
            role_arn = create_role(iam_client, role_name, assume_role_policy_document, permissions_boundary_arn, policy_json)
            if not role_arn:
                print(f"Failed to create and verify role '{role_name}' for profile {profile_name}.")
                time.sleep(10)
        else:
            role_arn = roles[0]['Arn']

        if roles:
            try:
                policies = iam_client.list_role_policies(RoleName=role_name)
                if "Ec2LambdaTaggerPolicy" not in policies['PolicyNames']:
                    iam_client.put_role_policy(
                        RoleName=role_name,
                        PolicyName="Ec2LambdaTaggerPolicy",
                        PolicyDocument=policy_json
                    )
                    print(f"Attached missing policy to role '{role_name}' for profile {profile_name}.")
            except ClientError as e:
                print(f"Failed to check or attach policy to existing role '{role_name}' for profile {profile_name}. Error: {e}")

        if role_arn:

            lambda_zip_file = "lambda_tagger.zip"
        
            with zipfile.ZipFile(lambda_zip_file, 'w') as z:
                z.write("lambda_tagger.py")

            try:
                response = lambda_client.get_function(FunctionName=lambda_function_name)
                lambda_function_arn = response['Configuration']['FunctionArn']
                print(f"Function {lambda_function_name} already exists for profile {profile_name}. Skipping creation.")
            except lambda_client.exceptions.ResourceNotFoundException:
                with open(lambda_zip_file, 'rb') as z:
                    try:
                        lambda_function_arn = lambda_client.create_function(
                            FunctionName=lambda_function_name,
                            Runtime='python3.9',
                            Role=role_arn,
                            Handler='lambda_tagger.lambda_handler',
                            Code={'ZipFile': z.read()}
                        )['FunctionArn']
                        print(f"Created Lambda function {lambda_function_name} for profile {profile_name}.")
                    except Exception as e:
                        print(f"Error creating Lambda function for profile {profile_name}: {e}")
            if lambda_function_arn:

                events_client = session.client('events')

                event_pattern = {
                    "source": ["aws.ec2"],
                    "detail-type": ["EC2 Instance State-change Notification"],
                    "detail": {
                        "state": ["pending"]
                    }
                }

                rule_response = events_client.put_rule(
                    Name=rule_name,
                    EventPattern=json.dumps(event_pattern),
                    State='ENABLED'
                )

                def permission_exists(lambda_client, function_name, statement_id):
                    try:
                        response = lambda_client.get_policy(FunctionName=function_name)
                        policy = json.loads(response['Policy'])
                        for statement in policy['Statement']:
                            if statement['Sid'] == statement_id:
                                return True
                        return False
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ResourceNotFoundException':
                            return False
                        else:
                            raise e

                if not permission_exists(lambda_client, lambda_function_name, "AllowCloudWatchToInvoke"):
                    lambda_client.add_permission(
                        FunctionName=lambda_function_name,
                        StatementId="AllowCloudWatchToInvoke",
                        Action="lambda:InvokeFunction",
                        Principal="events.amazonaws.com",
                        SourceArn=rule_response['RuleArn']
                    )

                events_client.put_targets(
                    Rule=rule_name,
                    Targets=[
                        {
                            'Id': 'ec2StartupTrigger',
                            'Arn': lambda_function_arn
                        }
                    ]
                )

                print(f"Setup completed for profile: {profile_name}")
            else:
                print(f"Lambda function was not created for profile {profile_name}. Skipping further setup.")

        else:
            print(f"Skipping Lambda deployment for profile {profile_name} due to missing role.")

    if os.path.exists(lambda_zip_file):
        os.remove(lambda_zip_file)
        print(f"Removed temporary file: {lambda_zip_file}")

    print("Script execution completed.")