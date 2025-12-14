.PHONY: test test-cov install clean lint format

install:
	pip install -r requirements.txt

test:
	pytest

test-cov:
	pytest --cov=argus_scan --cov-report=term-missing --cov-report=html --cov-fail-under=80

test-watch:
	pytest-watch

lint:
	flake8 argus_scan tests

format:
	black argus_scan tests

clean:
	find . -type d -name __pycache__ -exec rm -r {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

