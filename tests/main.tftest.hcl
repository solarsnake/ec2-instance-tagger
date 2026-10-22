mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws-us-gov"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-gov-west-1"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

run "defaults" {
  command = plan

  assert {
    condition     = aws_lambda_function.this.runtime == "python3.13"
    error_message = "Runtime must be python3.13."
  }

  assert {
    condition     = aws_lambda_function.this.architectures == tolist(["arm64"])
    error_message = "Architecture must be arm64."
  }

  assert {
    condition     = aws_iam_role.this.permissions_boundary == null
    error_message = "No permissions boundary by default."
  }

  assert {
    condition     = jsondecode(local.event_pattern).detail.state == ["pending"]
    error_message = "Rule must match the pending state."
  }

  assert {
    condition     = one([for s in jsondecode(local.policy).Statement : s.Resource if s.Sid == "TagInstances"]) == "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/*"
    error_message = "TagInstances must be scoped to instances in the current partition, region and account."
  }

  assert {
    condition     = one([for s in jsondecode(local.policy).Statement : s.Resource if s.Sid == "WriteLogs"]) == "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/lambda/ec2-instance-tagger:*"
    error_message = "WriteLogs must be scoped to the function log group."
  }

  assert {
    condition     = one([for s in jsondecode(local.policy).Statement : s.Action if s.Sid == "WriteLogs"]) == ["logs:CreateLogStream", "logs:PutLogEvents"]
    error_message = "WriteLogs must allow exactly CreateLogStream and PutLogEvents."
  }

  assert {
    condition     = one([for s in jsondecode(local.policy).Statement : s.Action if s.Sid == "DescribeInstances"]) == "ec2:DescribeInstances"
    error_message = "DescribeInstances must allow only ec2:DescribeInstances."
  }

  assert {
    condition     = one([for s in jsondecode(local.policy).Statement : s.Resource if s.Sid == "DescribeInstances"]) == "*"
    error_message = "DescribeInstances must apply to all resources."
  }

  assert {
    condition     = length([for s in jsondecode(local.policy).Statement : s if s.Resource == "*" && s.Sid != "DescribeInstances"]) == 0
    error_message = "Only DescribeInstances may use a wildcard resource."
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.OVERWRITE_EXISTING == "false"
    error_message = "OVERWRITE_EXISTING must default to false."
  }

  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 30
    error_message = "Log retention must default to 30 days."
  }

  assert {
    condition     = length(jsondecode(local.policy).Statement) == 3
    error_message = "The policy must have exactly three statements."
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.TAG_KEY == "os"
    error_message = "TAG_KEY must default to os."
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.SKIP_EKS_NODES == "true"
    error_message = "SKIP_EKS_NODES must default to true."
  }
}

run "tags_applied" {
  command = plan

  variables {
    tags = { team = "platform" }
  }

  assert {
    condition     = aws_cloudwatch_log_group.this.tags.team == "platform"
    error_message = "Tags must be applied to the log group."
  }

  assert {
    condition     = aws_iam_role.this.tags.team == "platform"
    error_message = "Tags must be applied to the IAM role."
  }

  assert {
    condition     = aws_lambda_function.this.tags.team == "platform"
    error_message = "Tags must be applied to the Lambda function."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.this.tags.team == "platform"
    error_message = "Tags must be applied to the event rule."
  }
}

run "boundary_applied_when_set" {
  command = plan

  variables {
    permissions_boundary_arn = "arn:aws-us-gov:iam::123456789012:policy/Boundary"
  }

  assert {
    condition     = aws_iam_role.this.permissions_boundary == "arn:aws-us-gov:iam::123456789012:policy/Boundary"
    error_message = "The permissions boundary must be applied to the role."
  }
}

run "custom_settings" {
  command = plan

  variables {
    tag_key            = "Platform"
    overwrite_existing = true
    skip_eks_nodes     = false
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.TAG_KEY == "Platform"
    error_message = "TAG_KEY must follow tag_key."
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.OVERWRITE_EXISTING == "true"
    error_message = "OVERWRITE_EXISTING must follow overwrite_existing."
  }

  assert {
    condition     = aws_lambda_function.this.environment[0].variables.SKIP_EKS_NODES == "false"
    error_message = "SKIP_EKS_NODES must follow skip_eks_nodes."
  }
}

run "rejects_empty_tag_key" {
  command = plan

  variables {
    tag_key = " "
  }

  expect_failures = [var.tag_key]
}

run "rejects_bad_retention" {
  command = plan

  variables {
    log_retention_days = 10
  }

  expect_failures = [var.log_retention_days]
}

run "rejects_bad_name_prefix" {
  command = plan

  variables {
    name_prefix = "bad name!"
  }

  expect_failures = [var.name_prefix]
}
