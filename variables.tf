variable "name_prefix" {
  description = "Name used for the Lambda function, IAM role, log group and as the prefix of the EventBridge rule."
  type        = string
  default     = "ec2-instance-tagger"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,47}$", var.name_prefix))
    error_message = "name_prefix must be 1-47 characters of letters, digits, hyphen or underscore."
  }
}

variable "tag_key" {
  description = "Key of the tag written to each instance."
  type        = string
  default     = "os"

  validation {
    condition     = length(trimspace(var.tag_key)) > 0 && length(var.tag_key) <= 128
    error_message = "tag_key must be non-empty and at most 128 characters."
  }
}

variable "overwrite_existing" {
  description = "Replace the tag when the instance already has it."
  type        = bool
  default     = false
}

variable "skip_eks_nodes" {
  description = "Skip instances that belong to an EKS cluster."
  type        = bool
  default     = true
}

variable "permissions_boundary_arn" {
  description = "Optional permissions boundary policy ARN for the Lambda role."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days. Must be a value CloudWatch Logs accepts."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be one of the values CloudWatch Logs accepts."
  }
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
