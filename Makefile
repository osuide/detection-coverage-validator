# A13E Detection Coverage Validator - Development Commands

.PHONY: setup lint format test pre-commit

# Install all development dependencies and pre-commit hooks
setup:
	@echo "Installing Python dependencies..."
	cd backend && pip install -r requirements.txt
	@echo "Installing pre-commit..."
	pip install pre-commit black ruff
	@echo "Installing pre-commit hooks..."
	python3 -m pre_commit install
	@echo "Installing frontend dependencies..."
	cd frontend && npm install
	@echo "Setup complete!"

# Run all linters (without fixing)
lint:
	@echo "Running Python linter (ruff)..."
	cd backend && python3 -m ruff check app/
	@echo "Running Python formatter check (black)..."
	cd backend && python3 -m black --check app/
	@echo "Running Terraform format check..."
	cd infrastructure/terraform && terraform fmt -check -recursive
	@echo "Running frontend linter (eslint)..."
	cd frontend && npm run lint
	@echo "All linters passed!"

# Format all code (auto-fix)
format:
	@echo "Formatting Python code (black)..."
	cd backend && python3 -m black app/
	@echo "Fixing Python lint issues (ruff)..."
	cd backend && python3 -m ruff check app/ --fix || true
	@echo "Formatting Terraform..."
	cd infrastructure/terraform && terraform fmt -recursive
	@echo "Formatting complete!"

# Run pre-commit on all files
pre-commit:
	python3 -m pre_commit run --all-files

# Run backend tests
test-backend:
	cd backend && pytest

# Run frontend type check
test-frontend:
	cd frontend && npm run type-check

# Run all tests
test: test-backend test-frontend
