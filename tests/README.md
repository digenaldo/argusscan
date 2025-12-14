# Tests

This directory contains unit tests for ArgusScan.

## Running Tests

### Run all tests
```bash
pytest
```

### Run with coverage
```bash
pytest --cov=argus_scan --cov-report=term-missing --cov-fail-under=80
```

### Run specific test file
```bash
pytest tests/test_argus_scan.py
```

### Run specific test
```bash
pytest tests/test_argus_scan.py::TestLoadConfig::test_load_config_with_api_key
```

## Coverage Requirements

Tests must maintain at least **80% code coverage**. The CI/CD pipeline will fail if coverage drops below this threshold.

## Test Structure

- `test_argus_scan.py`: Main unit tests for core functionality
- `conftest.py`: Pytest fixtures and configuration

## Writing Tests

Follow these guidelines:
- Use descriptive test names
- One assertion per test when possible
- Use fixtures for common test data
- Mock external dependencies (Shodan API, file system, etc.)

