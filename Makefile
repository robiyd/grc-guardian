.PHONY: help venv install test run lint format clean

# Default target
help:
	@echo "GRC Guardian - Available targets:"
	@echo "  make venv      - Create virtual environment and install dependencies"
	@echo "  make install   - Install dependencies only"
	@echo "  make test      - Run all tests with coverage"
	@echo "  make run       - Start the FastAPI service"
	@echo "  make lint      - Run linting checks (ruff, mypy)"
	@echo "  make format    - Format code with black and isort"
	@echo "  make clean     - Remove generated files and caches"

# Python executable
PYTHON := python3.11
VENV := venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip

# Create virtual environment and install dependencies
venv:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "Installing dependencies..."
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e ".[dev,reports,terraform]"
	@echo "Virtual environment ready! Activate with: source $(VENV_BIN)/activate"

# Install dependencies (assumes venv exists)
install:
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,reports,terraform]"

# Run tests with coverage
test:
	@echo "Running tests..."
	$(VENV_BIN)/pytest -v --cov-report=term-missing

# Run the FastAPI service
run:
	@echo "Starting GRC Guardian API service..."
	$(VENV_BIN)/uvicorn api.app.main:app --reload --host 0.0.0.0 --port 8000

# Run linting
lint:
	@echo "Running linting checks..."
	$(VENV_BIN)/ruff check .
	$(VENV_BIN)/mypy api/ agent/ tools/ rag/ evidence/ reports/
	@echo "Linting complete!"

# Format code
format:
	@echo "Formatting code..."
	$(VENV_BIN)/black .
	$(VENV_BIN)/isort .
	$(VENV_BIN)/ruff check --fix .
	@echo "Code formatted!"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage build/ dist/
	@echo "Clean complete!"
