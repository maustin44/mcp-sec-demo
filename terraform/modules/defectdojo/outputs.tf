output "defectdojo_url" {
  description = "Public URL of DefectDojo"
  value       = "http://${aws_lb.defectdojo.dns_name}"
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.defectdojo.dns_name
}
