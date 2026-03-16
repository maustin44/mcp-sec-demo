output "cloudfront_url" {
  value = "https://${aws_cloudfront_distribution.spa.domain_name}"
}

output "bucket_name" {
  value = aws_s3_bucket.spa.bucket
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.spa.id
}
