terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# --- INFRASTRUCTURE COMPLIANCE DRIFT ENGINE (THE SABOTAGE) ---

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-ssh-access"
  description = "Intentionally insecure security group for audit evaluation"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Non-compliant: Open SSH port
  }
}

# Generate a random 4-byte string to ensure globally unique bucket and role names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "titan-fintech-compliance-drift-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "vulnerable_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false # Non-compliant: Public access enabled
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# --- AWS CONFIG RECORDER MANAGEMENT (THE AUDITOR) ---

resource "aws_iam_role" "config_role" {
  name = "aws-config-compliance-role-${random_id.bucket_suffix.hex}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

# Attach the official AWS Config managed policy so the role has permissions
resource "aws_iam_role_policy_attachment" "config_policy_attach" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "audit_recorder" {
  name     = "compliance-audit-recorder"
  role_arn = aws_iam_role.config_role.arn
}

# Create a bucket for AWS Config to store its history logs
resource "aws_s3_bucket" "config_logs_bucket" {
  bucket        = "titan-fintech-config-logs-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

# Bucket Policy granting AWS Config explicit access to write logs
resource "aws_s3_bucket_policy" "config_logs_policy" {
  bucket = aws_s3_bucket.config_logs_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_logs_bucket.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_logs_bucket.arn}/*"
      }
    ]
  })
}

# Create the Delivery Channel pointing to the logs bucket
resource "aws_config_delivery_channel" "audit_channel" {
  name           = "compliance-audit-channel"
  s3_bucket_name = aws_s3_bucket.config_logs_bucket.bucket
  depends_on     = [
    aws_config_configuration_recorder.audit_recorder,
    aws_s3_bucket_policy.config_logs_policy
  ]
}

# Explicitly turn the Recorder ON
resource "aws_config_configuration_recorder_status" "audit_recorder_status" {
  name       = aws_config_configuration_recorder.audit_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.audit_channel]
}

resource "aws_config_config_rule" "ssh_rule" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED" 
  }
  depends_on = [
    aws_config_configuration_recorder.audit_recorder,
    aws_config_configuration_recorder_status.audit_recorder_status
  ]
}

resource "aws_config_config_rule" "s3_rule" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [
    aws_config_configuration_recorder.audit_recorder,
    aws_config_configuration_recorder_status.audit_recorder_status
  ]
}