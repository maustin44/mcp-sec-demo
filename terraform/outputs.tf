output "cloudfront_url" {
  description = "Public URL of the SPA"
  value       = module.spa_hosting.cloudfront_url
}

output "s3_bucket_name" {
  description = "S3 bucket hosting the SPA"
  value       = module.spa_hosting.bucket_name
}

output "defectdojo_url" {
  description = "Public URL of DefectDojo"
  value       = module.defectdojo.defectdojo_url
}
