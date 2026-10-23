provider "aws" {}

module "tagger" {
  source = "../.."
}

output "function_name" {
  value = module.tagger.function_name
}
