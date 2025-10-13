.PHONY: help install test lint format deploy destroy clean

# Default target
help:
	@echo "Available commands:"
	@echo "  install                - Install developlement dependencies"
	@echo "  test                   - Run tests"
	@echo "  lint                   - Run linting"
	@echo "  format                 - Format code"
	@echo "  bootstrap              - Bootstrap Terraform"
	@echo "  deploy                 - Deploy infrastructure in AWS"
	@echo "  destroy                - Destroy AWS resources"
	@echo "  validate-config        - Validate routes configuration"
	@echo "  example-param-creation - Example command to create a parameter for Authru"

# Install dependencies
install:
	pip install -r requirements-dev.txt

# Run tests
test:
	python -m pytest

# Lint Python code
lint:
	flake8 src tests
	mypy src

# Format Python & terraform code
format:
	black src tests
	cd terraform && terraform fmt

# Clean build artifacts
clean:
	rm -rf .pytest_cache
	rm -rf __pycache__
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.pyc" -delete

# Local development setup
dev-setup: install
	@echo "Setting up development environment..."
	@echo "1. Configure AWS CLI: aws configure"
	@echo "2. Bootstrap CDK: make bootstrap"
	@echo "3. Update config/routes.json with your settings"
	@echo "4. Deploy: make deploy"

# Validate configuration
validate-config:
	python -c "from src.config.loader import ConfigLoader; ConfigLoader('config/routes.json').load_config(); print('Configuration is valid')"

# Example command to create a parameter for Authru
example-param-creation:
	@echo "Example command to create a parameter for Authru"
	@echo "aws ssm put-parameter \
		   --name "/authru/tokens/example-api" \
		   --value "your-username:your-password" \
		   --type "SecureString" \
		   --description \"Example API credentials for Authru\" \
		   --region eu-west-1 \
		   --overwrite"

# Terraform related commands
bootstrap:
	cd terraform/bootstrap && terraform init && terraform plan && terraform apply

destroy:
	cd terraform/infrastructure && terraform destroy

deploy:
	cd terraform/infrastructure && terraform init && terraform plan && terraform apply
