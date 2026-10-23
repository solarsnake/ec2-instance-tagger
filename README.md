# EC2 Instance Tagger

[![CI](https://github.com/solarsnake/ec2-instance-tagger/actions/workflows/ci.yml/badge.svg)](https://github.com/solarsnake/ec2-instance-tagger/actions/workflows/ci.yml)

A small Terraform module that tags each EC2 instance in a region with its OS family (`windows`, `rhel`, `suse`, `linux`) the moment it launches.

## How it works

An EventBridge rule matches EC2 state-change events for the `pending` state and invokes a Lambda function. The function reads the instance's `PlatformDetails` and writes the tag.

The zip is built at plan time under the module's `build/` directory.

`PlatformDetails` is the billing platform, so Ubuntu, Amazon Linux and other free distributions all report `linux`.

## Requirements

- Terraform >= 1.7
- AWS provider >= 6.0
- Archive provider (hashicorp/archive) >= 2.4

## Usage

```hcl
module "ec2_instance_tagger" {
  source = "github.com/solarsnake/ec2-instance-tagger"
}
```

To pin a version, add `?ref=<tag or commit SHA>` to the source, for example `source = "github.com/solarsnake/ec2-instance-tagger?ref=<tag or commit SHA>"`.

## Example output

Each invocation writes one JSON line to the function's CloudWatch log group:

```json
{"instance_id": "i-0123456789abcdef0", "action": "tagged", "reason": null, "value": "windows", "tag_key": "os"}
```

When nothing is tagged, `action` is `skipped` and `reason` is one of:

- `bad-event`: the event has no instance ID.
- `not-found`: the instance does not exist (checked up to 3 times, to allow for EC2 eventual consistency after launch).
- `eks-node`: the instance belongs to an EKS cluster and `skip_eks_nodes` is true.
- `tag-exists`: the instance already has the tag and `overwrite_existing` is false.

## Safety notes

- The module only ever adds one tag and never removes any.
- An existing tag is kept unless `overwrite_existing` is true.
- `pending` also fires when a stopped instance starts. That is harmless because the tagging is idempotent.

## Inputs

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name_prefix` | `string` | `"ec2-instance-tagger"` | Name used for the Lambda function, IAM role, log group and as the prefix of the EventBridge rule. |
| `tag_key` | `string` | `"os"` | Key of the tag written to each instance. |
| `overwrite_existing` | `bool` | `false` | Replace the tag when the instance already has it. |
| `skip_eks_nodes` | `bool` | `true` | Skip instances that belong to an EKS cluster. |
| `permissions_boundary_arn` | `string` | `null` | Optional permissions boundary policy ARN for the Lambda role. |
| `log_retention_days` | `number` | `30` | CloudWatch log retention in days. Must be a value CloudWatch Logs accepts. |
| `tags` | `map(string)` | `{}` | Tags applied to every taggable resource. |

## Outputs

| Name | Description |
|------|-------------|
| `function_name` | Name of the Lambda function. |
| `function_arn` | ARN of the Lambda function. |
| `role_arn` | ARN of the Lambda execution role. |
| `event_rule_arn` | ARN of the EventBridge rule. |

## Multiple regions

One module instance covers one region, because EventBridge rules are regional. The IAM role name is global, so use a different `name_prefix` for each additional region:

```hcl
provider "aws" {
  alias  = "usw2"
  region = "us-west-2"
}

module "ec2_instance_tagger_usw2" {
  source      = "github.com/solarsnake/ec2-instance-tagger"
  name_prefix = "ec2-instance-tagger-usw2"

  providers = {
    aws = aws.usw2
  }
}
```

## Multiple accounts

Deploy one state per account, each with its own provider configuration. Each `envs/<profile>` directory is a small root module that calls this module.

```bash
for p in dev prod; do AWS_PROFILE=$p terraform -chdir=envs/$p apply; done
```

## IAM permissions

The Lambda role has an inline policy with three statements:

| Sid | Action | Resource |
|-----|--------|----------|
| `DescribeInstances` | `ec2:DescribeInstances` | `*` |
| `TagInstances` | `ec2:CreateTags` | `arn:<partition>:ec2:<region>:<account>:instance/*` |
| `WriteLogs` | `logs:CreateLogStream`, `logs:PutLogEvents` | `arn:<partition>:logs:<region>:<account>:log-group:/aws/lambda/<name_prefix>:*` |

## GovCloud

It works unchanged. The partition, region and account are read from the provider, so no ARN is hard-coded.

## Upgrading from deploy.py

The old script created resources by hand, so Terraform does not know about them. Delete them before applying the module, in this order:

```bash
aws events remove-targets --rule EC2LaunchRule --ids ec2StartupTrigger
aws events delete-rule --name EC2LaunchRule
aws lambda delete-function --function-name EC2Tagger
aws iam delete-role-policy --role-name Ec2LambdaTaggerRole --policy-name Ec2LambdaTaggerPolicy
aws iam delete-role --role-name Ec2LambdaTaggerRole
aws logs delete-log-group --log-group-name /aws/lambda/EC2Tagger
```

Run these once per account and region that `deploy.py` was used in.

## Running the tests

Requires Python 3.11+ and Terraform.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
terraform init -backend=false
terraform fmt -check -recursive && terraform validate
terraform test
```

## License

GPLv3 (GPL-3.0-or-later). See [LICENSE](LICENSE).
