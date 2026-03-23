# -----------------------------------------------------------------------
# DefectDojo on ECS Fargate + RDS PostgreSQL + ElastiCache Redis
# -----------------------------------------------------------------------

data "aws_availability_zones" "available" {}

# --- VPC & Networking ---
resource "aws_vpc" "defectdojo" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project}-${var.environment}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.defectdojo.id
  cidr_block              = cidrsubnet(aws_vpc.defectdojo.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = { Name = "${var.project}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.defectdojo.id
  cidr_block        = cidrsubnet(aws_vpc.defectdojo.cidr_block, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = { Name = "${var.project}-private-${count.index}" }
}

resource "aws_internet_gateway" "defectdojo" {
  vpc_id = aws_vpc.defectdojo.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.defectdojo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.defectdojo.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Security Groups ---
resource "aws_security_group" "alb" {
  name   = "${var.project}-alb-sg"
  vpc_id = aws_vpc.defectdojo.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name   = "${var.project}-ecs-sg"
  vpc_id = aws_vpc.defectdojo.id
  ingress {
    from_port       = 8081
    to_port         = 8081
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds" {
  name   = "${var.project}-rds-sg"
  vpc_id = aws_vpc.defectdojo.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "redis" {
  name   = "${var.project}-redis-sg"
  vpc_id = aws_vpc.defectdojo.id
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- RDS PostgreSQL ---
resource "aws_db_subnet_group" "defectdojo" {
  name       = "${var.project}-${var.environment}-db-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "defectdojo" {
  identifier        = "${var.project}-${var.environment}-db"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "defectdojo"
  username = "defectdojo"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.defectdojo.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  deletion_protection    = false
}

# --- ElastiCache Redis (Celery broker) ---
resource "aws_elasticache_subnet_group" "defectdojo" {
  name       = "${var.project}-${var.environment}-redis-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_cluster" "defectdojo" {
  cluster_id           = "${var.project}-${var.environment}"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  engine_version       = "7.0"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.defectdojo.name
  security_group_ids   = [aws_security_group.redis.id]
}

# --- ECS Cluster ---
resource "aws_ecs_cluster" "defectdojo" {
  name = "${var.project}-${var.environment}"
}

# --- IAM ---
resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.project}-ecs-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# SSM policy for ECS exec (manage.py migrate, debugging)
resource "aws_iam_role_policy" "ecs_task_ssm" {
  name = "${var.project}-ecs-ssm"
  role = aws_iam_role.ecs_task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ]
      Resource = "*"
    }]
  })
}

# --- ECS Task Definition ---
resource "aws_ecs_task_definition" "defectdojo" {
  family                   = "${var.project}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "defectdojo"
      image     = "defectdojo/defectdojo-django:latest"
      essential = true
      portMappings = [{ containerPort = 8081, hostPort = 8081 }]
      environment = [
        { name = "DD_DATABASE_URL",          value = "postgresql://defectdojo:${var.db_password}@${aws_db_instance.defectdojo.address}:5432/defectdojo" },
        { name = "DD_CELERY_BROKER_URL",     value = "redis://${aws_elasticache_cluster.defectdojo.cache_nodes[0].address}:6379/0" },
        { name = "DD_SECRET_KEY",            value = var.dd_secret_key },
        { name = "DD_ALLOWED_HOSTS",         value = "*" },
        { name = "DD_DJANGO_ADMIN_ENABLED",  value = "true" },
        { name = "DD_SESSION_COOKIE_SECURE", value = "False" },
        { name = "DD_PORT",                  value = "8081" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${var.project}-${var.environment}"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "defectdojo"
        }
      }
    }
  ])
}

# --- CloudWatch Logs ---
resource "aws_cloudwatch_log_group" "defectdojo" {
  name              = "/ecs/${var.project}-${var.environment}"
  retention_in_days = 30
}

# --- ALB ---
resource "aws_lb" "defectdojo" {
  name               = "${var.project}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "defectdojo" {
  name        = "${var.project}-${var.environment}-tg"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = aws_vpc.defectdojo.id
  target_type = "ip"

  health_check {
    path                = "/login"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    timeout             = 30
    interval            = 60
    matcher             = "200,301,302"
  }
}

resource "aws_lb_listener" "defectdojo" {
  load_balancer_arn = aws_lb.defectdojo.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.defectdojo.arn
  }
}

# --- ECS Service ---
resource "aws_ecs_service" "defectdojo" {
  name                   = "${var.project}-${var.environment}"
  cluster                = aws_ecs_cluster.defectdojo.id
  task_definition        = aws_ecs_task_definition.defectdojo.arn
  desired_count          = 1
  launch_type            = "FARGATE"
  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.defectdojo.arn
    container_name   = "defectdojo"
    container_port   = 8081
  }

  depends_on = [aws_lb_listener.defectdojo, aws_elasticache_cluster.defectdojo]
}
