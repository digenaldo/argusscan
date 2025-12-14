"""
Pytest configuration and fixtures
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_host():
    """Sample host data for testing"""
    return {
        'ip': '192.168.1.1',
        'hostnames': ['test.example.com'],
        'port': 80,
        'org': 'Test Organization',
        'isp': 'Test ISP',
        'location': {
            'country_name': 'US',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        },
        'banner': 'HTTP/1.1 200 OK\nServer: Apache/2.4.41',
        'product': 'Apache',
        'version': '2.4.41',
        'vulns': {
            'CVE-2024-1234': {
                'verified': True,
                'cvss': 7.5
            }
        },
        'timestamp': '2024-01-01T00:00:00',
        'shodan_link': 'https://www.shodan.io/host/192.168.1.1',
        'direct_link': 'http://192.168.1.1:80'
    }


@pytest.fixture
def sample_hosts(sample_host):
    """Sample hosts list for testing"""
    return [sample_host]


@pytest.fixture
def mock_shodan_api():
    """Mock Shodan API for testing"""
    from unittest.mock import Mock
    mock_api = Mock()
    mock_api.search.return_value = {
        'matches': [
            {
                'ip_str': '192.168.1.1',
                'hostnames': ['test.example.com'],
                'port': 80,
                'org': 'Test Organization',
                'isp': 'Test ISP',
                'location': {
                    'country_name': 'US',
                    'city': 'New York'
                },
                'data': 'HTTP/1.1 200 OK',
                'product': 'Apache',
                'version': '2.4.41',
                'vulns': {'CVE-2024-1234': {}},
                'timestamp': '2024-01-01T00:00:00'
            }
        ]
    }
    return mock_api

