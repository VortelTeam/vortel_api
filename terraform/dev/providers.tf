terraform {
  backend "s3" {
    bucket = "vortel-backend-storage"
    key    = "terraform/terraform.tfstate"
    region = "us-west-2"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.87.0"
    }
  }
}

locals {
  project_name = "vortel-backend"
}

provider "aws" {
  region = "us-west-2"
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = local.project_name
    }
  }
}
