data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  log_group_name = "/aws/lambda/${var.name_prefix}"
  log_group_arn  = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.log_group_name}:*"
  instance_arn   = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:instance/*"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["EC2 Instance State-change Notification"]
    detail        = { state = ["pending"] }
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DescribeInstances"
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances"
        Resource = "*"
      },
      {
        Sid      = "TagInstances"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = local.instance_arn
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.log_group_arn
      },
    ]
  })
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/src/lambda_tagger.py"
  output_path = "${path.module}/build/lambda_tagger.zip"

  output_file_mode = "0644"
}

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "this" {
  name                 = var.name_prefix
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "this" {
  name   = var.name_prefix
  role   = aws_iam_role.this.id
  policy = local.policy
}

resource "aws_lambda_function" "this" {
  function_name    = var.name_prefix
  role             = aws_iam_role.this.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "lambda_tagger.lambda_handler"
  timeout          = 30
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  tags             = var.tags

  environment {
    variables = {
      TAG_KEY            = var.tag_key
      OVERWRITE_EXISTING = tostring(var.overwrite_existing)
      SKIP_EKS_NODES     = tostring(var.skip_eks_nodes)
    }
  }

  depends_on = [aws_cloudwatch_log_group.this]
}

resource "aws_cloudwatch_event_rule" "this" {
  name          = "${var.name_prefix}-instance-pending"
  event_pattern = local.event_pattern
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "this" {
  rule      = aws_cloudwatch_event_rule.this.name
  target_id = "lambda"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
