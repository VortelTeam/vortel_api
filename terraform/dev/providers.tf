terraform {
  backend "s3" {
    bucket = "vortel-backend-storage"
    key    = "terraform/terraform.tfstate"
    region = "ca-central-1"
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
  region = "ca-central-1"
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = local.project_name
    }
  }
}
