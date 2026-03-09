.PHONY: test lint security install-dev all

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	FLASK_SECRET_KEY=dev-secret \
	DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" \
	MSTDNCA_DATA_DIR=/tmp/mstdnca-dev \
	pytest tests/ -v --cov=. --cov-report=term-missing --cov-fail-under=18

lint:
	ruff check .

security:
	bandit -r . -c pyproject.toml
	pip-audit -r requirements.txt

all: lint security test
