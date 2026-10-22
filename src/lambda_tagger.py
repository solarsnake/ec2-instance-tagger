"""Tag newly launched EC2 instances with their operating system family."""

import json
import os

import boto3
from botocore.exceptions import ClientError

EKS_TAGS = ("eks:nodegroup-name", "eks:cluster-name", "karpenter.sh/nodepool")


def classify_platform(platform_details: str | None) -> str:
    """Map an EC2 PlatformDetails string to windows, rhel, suse or linux."""
    text = (platform_details or "").lower()
    if "windows" in text:
        return "windows"
    if "red hat" in text:
        return "rhel"
    if "suse" in text:
        return "suse"
    return "linux"


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean flag; true, 1 and yes (any case) are true, anything else is false."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")


def _ec2_client():
    return boto3.client("ec2")


def _log(tag_key: str, **fields) -> None:
    print(json.dumps({**fields, "tag_key": tag_key}))


def lambda_handler(event: dict, context) -> dict:
    tag_key = os.environ.get("TAG_KEY", "os")
    overwrite = _env_bool("OVERWRITE_EXISTING", False)
    skip_eks = _env_bool("SKIP_EKS_NODES", True)

    def decide(instance_id, action, reason=None, value=None) -> dict:
        result = {"instance_id": instance_id, "action": action, "reason": reason, "value": value}
        _log(tag_key, **result)
        return result

    detail = event.get("detail") if isinstance(event, dict) else None
    instance_id = detail.get("instance-id") if isinstance(detail, dict) else None
    if not instance_id:
        return decide(None, "skipped", "bad-event")

    ec2 = _ec2_client()
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return decide(instance_id, "skipped", "not-found")
        _log(tag_key, instance_id=instance_id, action="error", error=str(err))
        raise

    instances = [i for r in response.get("Reservations", []) for i in r.get("Instances", [])]
    if not instances:
        return decide(instance_id, "skipped", "not-found")
    instance = instances[0]

    tags = {t["Key"]: t.get("Value") for t in instance.get("Tags", [])}
    if skip_eks and any(key in tags for key in EKS_TAGS):
        return decide(instance_id, "skipped", "eks-node")
    if tag_key in tags and not overwrite:
        return decide(instance_id, "skipped", "tag-exists")

    value = classify_platform(instance.get("PlatformDetails"))
    try:
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": tag_key, "Value": value}])
    except ClientError as err:
        _log(tag_key, instance_id=instance_id, action="error", error=str(err))
        raise
    return decide(instance_id, "tagged", value=value)
