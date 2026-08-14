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

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "titan-fintech-compliance-drift-bucket"
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

resource "aws_config_configuration_recorder" "audit_recorder" {
  name     = "compliance-audit-recorder"
  role_arn = aws_iam_role.config_role.arn
}

resource "aws_iam_role" "config_role" {
  name = "aws-config-compliance-role"

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

resource "aws_config_config_rule" "ssh_rule" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INSECURE_SSH_RULE"
  }
  depends_on = [aws_config_configuration_recorder.audit_recorder]
}

resource "aws_config_config_rule" "s3_rule" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.audit_recorder]
}
