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
    condition     = aws_lambda_function.this.environment[0].variables.OVERWRITE_EXISTING == "false"
    error_message = "OVERWRITE_EXISTING must default to false."
  }

  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 30
    error_message = "Log retention must default to 30 days."
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
