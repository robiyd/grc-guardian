# =============================================================================
# S3 Buckets for Simulated Organization
# =============================================================================

# -----------------------------------------------------------------------------
# 1. COMPLIANT: org-prod-logs-private
# Block public access ON, encryption ON, versioning ON
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "prod_logs_private" {
  bucket = "org-prod-logs-private-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "org-prod-logs-private"
    Environment = "prod"
    App         = "grc-guardian"
    Owner       = var.owner
    Compliance  = "COMPLIANT"
  }
}

resource "aws_s3_bucket_public_access_block" "prod_logs_private" {
  bucket = aws_s3_bucket.prod_logs_private.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "prod_logs_private" {
  bucket = aws_s3_bucket.prod_logs_private.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_logs_private" {
  bucket = aws_s3_bucket.prod_logs_private.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# 2. COMPLIANT: org-dev-backups-encrypted
# Block public access ON, encryption ON, versioning ON
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "dev_backups_encrypted" {
  bucket = "org-dev-backups-encrypted-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "org-dev-backups-encrypted"
    Environment = "dev"
    App         = "grc-guardian"
    Owner       = var.owner
    Compliance  = "COMPLIANT"
  }
}

resource "aws_s3_bucket_public_access_block" "dev_backups_encrypted" {
  bucket = aws_s3_bucket.dev_backups_encrypted.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "dev_backups_encrypted" {
  bucket = aws_s3_bucket.dev_backups_encrypted.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dev_backups_encrypted" {
  bucket = aws_s3_bucket.dev_backups_encrypted.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# 3. NONCOMPLIANT: org-prod-assets-public
# Intentionally public with Principal="*", block public access OFF
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "prod_assets_public" {
  bucket = "org-prod-assets-public-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "org-prod-assets-public"
    Environment = "prod"
    App         = "grc-guardian"
    Owner       = var.owner
    Compliance  = "NONCOMPLIANT"
  }
}

# Explicitly allow public access (block public access OFF)
resource "aws_s3_bucket_public_access_block" "prod_assets_public" {
  bucket = aws_s3_bucket.prod_assets_public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Public read policy
resource "aws_s3_bucket_policy" "prod_assets_public" {
  bucket = aws_s3_bucket.prod_assets_public.id

  depends_on = [aws_s3_bucket_public_access_block.prod_assets_public]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.prod_assets_public.arn}/*"
      }
    ]
  })
}

# Has versioning enabled (partial compliance)
resource "aws_s3_bucket_versioning" "prod_assets_public" {
  bucket = aws_s3_bucket.prod_assets_public.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Has encryption enabled (partial compliance)
resource "aws_s3_bucket_server_side_encryption_configuration" "prod_assets_public" {
  bucket = aws_s3_bucket.prod_assets_public.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# 4. NONCOMPLIANT: org-dev-data-unencrypted
# No encryption, no versioning (but block public access ON)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "dev_data_unencrypted" {
  bucket = "org-dev-data-unencrypted-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "org-dev-data-unencrypted"
    Environment = "dev"
    App         = "grc-guardian"
    Owner       = var.owner
    Compliance  = "NONCOMPLIANT"
  }
}

resource "aws_s3_bucket_public_access_block" "dev_data_unencrypted" {
  bucket = aws_s3_bucket.dev_data_unencrypted.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Explicitly no encryption (commented out to show intent)
# resource "aws_s3_bucket_server_side_encryption_configuration" "dev_data_unencrypted" {
#   # Intentionally not configured - NONCOMPLIANT
# }

# Explicitly no versioning (disabled)
resource "aws_s3_bucket_versioning" "dev_data_unencrypted" {
  bucket = aws_s3_bucket.dev_data_unencrypted.id

  versioning_configuration {
    status = "Disabled"
  }
}
