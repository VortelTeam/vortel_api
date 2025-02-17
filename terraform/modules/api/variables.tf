variable "environment" {
  description = "The name of the environment."
  type        = string
  nullable    = false
}

variable "project_name" {
  description = "The name of the project."
  type        = string
  nullable    = false
}

variable "lambda_storage_bucket" {
  type     = string
  nullable = false
}

variable "user_files_bucket" {
  type = object({
    name = string
    arn  = string
  })
  nullable = false
}


variable "metadata_table" {
  type = object({
    name = string
    arn  = string
  })
  nullable = false
}

variable "jobs_queue" {
  type = object({
    name = string
    arn  = string
  })
  nullable = false
}

variable "jobs_status_table" {
  type = object({
    name = string
    arn  = string
  })
  nullable = false
}

variable "output_bucket" {
  type = object({
    name = string
    arn  = string
  })
  nullable = false
}
