import boto3
import json

def lambda_handler(event, context):
    ec2_client = boto3.client('ec2')

    # Check if the launched instance is an EKS worker node
    instance_id = event['detail']['instance-id']
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    for r in response['Reservations']:
        for instance in r['Instances']:
            tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
            if tags.get('eks:nodegroup-name'):
                print(f"Instance {instance_id} is an EKS worker node. Skipping tagging.")
                return

    # Tag based on the OS type
    platform_details = instance.get('PlatformDetails', '')
    if 'windows' in platform_details.lower():
        os_value = 'windows'
    elif 'red hat' in platform_details.lower():
        os_value = 'rhel'
    else:
        os_value = 'linux'

    ec2_client.create_tags(Resources=[instance_id], Tags=[{'Key': 'os', 'Value': os_value}])