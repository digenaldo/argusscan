"""
Unit tests for argus_scan.py
"""
import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import json
import yaml

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from argus_scan import (
    load_config,
    rate_limit,
    search_shodan,
    display_results_table,
    generate_report,
    generate_basic_markdown,
    export_csv,
    CONFIG_FILE,
    REPORTS_DIR,
    TEMPLATE_FILE
)


class TestLoadConfig:
    """Tests for load_config function"""
    
    def test_load_config_with_api_key(self):
        """Test load_config with API key provided"""
        result = load_config(api_key="test_api_key")
        assert result['shodan_api_key'] == "test_api_key"
    
    @patch('argus_scan.CONFIG_FILE')
    @patch('builtins.open', new_callable=mock_open, read_data='shodan_api_key: "test_key"')
    @patch('yaml.safe_load')
    def test_load_config_from_file(self, mock_yaml, mock_file, mock_config_file):
        """Test load_config loading from config.yaml"""
        mock_config_file.exists.return_value = True
        mock_yaml.return_value = {'shodan_api_key': 'test_key'}
        
        result = load_config()
        assert result['shodan_api_key'] == 'test_key'
    
    @patch('argus_scan.CONFIG_FILE')
    @patch('sys.exit')
    def test_load_config_no_file_no_key(self, mock_exit, mock_config_file):
        """Test load_config when no file and no key provided"""
        mock_config_file.exists.return_value = False
        
        load_config()
        mock_exit.assert_called_once()


class TestRateLimit:
    """Tests for rate_limit function"""
    
    @patch('argus_scan.time')
    def test_rate_limit_waits_when_needed(self, mock_time):
        """Test rate limit waits when elapsed time is less than limit"""
        import argus_scan
        argus_scan.last_request_time = 0
        mock_time.time.return_value = 0.5  # 0.5 seconds elapsed
        
        rate_limit()
        mock_time.sleep.assert_called_once()
    
    @patch('argus_scan.time')
    def test_rate_limit_no_wait_when_enough_time(self, mock_time):
        """Test rate limit doesn't wait when enough time has passed"""
        import argus_scan
        argus_scan.last_request_time = 0
        mock_time.time.return_value = 2.0  # 2 seconds elapsed (more than 1.0 limit)
        
        rate_limit()
        mock_time.sleep.assert_not_called()


class TestSearchShodan:
    """Tests for search_shodan function"""
    
    @patch('argus_scan.rate_limit')
    def test_search_shodan_success(self, mock_rate_limit):
        """Test successful Shodan search"""
        mock_api = Mock()
        mock_api.search.return_value = {
            'matches': [
                {
                    'ip_str': '192.168.1.1',
                    'hostnames': ['test.com'],
                    'port': 80,
                    'org': 'Test Org',
                    'isp': 'Test ISP',
                    'location': {'country_name': 'US'},
                    'data': 'HTTP/1.1 200 OK',
                    'product': 'Apache',
                    'version': '2.4',
                    'vulns': {'CVE-2024-1234': {}},
                    'timestamp': '2024-01-01T00:00:00'
                }
            ]
        }
        
        result = search_shodan(mock_api, "test query")
        
        assert len(result) == 1
        assert result[0]['ip'] == '192.168.1.1'
        assert result[0]['port'] == 80
        assert result[0]['org'] == 'Test Org'
        mock_rate_limit.assert_called_once()
    
    @patch('argus_scan.rate_limit')
    def test_search_shodan_with_filters(self, mock_rate_limit):
        """Test Shodan search with filters"""
        mock_api = Mock()
        mock_api.search.return_value = {'matches': []}
        
        filters = {'country': 'BR', 'port': '80'}
        search_shodan(mock_api, "test", filters)
        
        # Verify query includes filters
        call_args = mock_api.search.call_args[0][0]
        assert 'country:"BR"' in call_args
        assert 'port:80' in call_args
    
    @patch('argus_scan.rate_limit')
    @patch('sys.exit')
    def test_search_shodan_api_error(self, mock_exit, mock_rate_limit):
        """Test Shodan search handles API errors"""
        import shodan
        mock_api = Mock()
        mock_api.search.side_effect = shodan.APIError("Invalid API key")
        
        search_shodan(mock_api, "test")
        mock_exit.assert_called_once()


class TestDisplayResultsTable:
    """Tests for display_results_table function"""
    
    @patch('argus_scan.console')
    def test_display_results_table_empty(self, mock_console):
        """Test display table with empty hosts"""
        display_results_table([], "test query")
        mock_console.print.assert_called()
    
    @patch('argus_scan.console')
    def test_display_results_table_with_hosts(self, mock_console):
        """Test display table with hosts"""
        hosts = [
            {
                'ip': '192.168.1.1',
                'port': 80,
                'org': 'Test Org',
                'product': 'Apache',
                'version': '2.4',
                'vulns': {'CVE-2024-1234': {}}
            }
        ]
        display_results_table(hosts, "test query")
        mock_console.print.assert_called()


class TestGenerateReport:
    """Tests for generate_report function"""
    
    @patch('argus_scan.REPORTS_DIR')
    @patch('argus_scan.console')
    def test_generate_report_no_hosts(self, mock_console, mock_reports_dir):
        """Test generate report with no hosts"""
        generate_report([], "test query")
        mock_console.print.assert_called_with("[yellow]Warning: No hosts to generate report[/yellow]")
    
    @patch('argus_scan.REPORTS_DIR')
    @patch('argus_scan.datetime')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    @patch('argus_scan.console')
    def test_generate_report_json(self, mock_console, mock_json, mock_file, mock_datetime, mock_reports_dir):
        """Test generate JSON report"""
        mock_reports_dir.mkdir = Mock()
        mock_datetime.now.return_value.strftime.return_value = "20240101_120000"
        
        hosts = [{'ip': '192.168.1.1', 'port': 80}]
        result = generate_report(hosts, "test query", 'json')
        
        assert result is not None
        mock_json.assert_called_once()
    
    @patch('argus_scan.REPORTS_DIR')
    @patch('argus_scan.TEMPLATE_FILE')
    @patch('argus_scan.datetime')
    @patch('builtins.open', new_callable=mock_open)
    @patch('argus_scan.console')
    def test_generate_report_markdown_with_template(self, mock_console, mock_file, mock_datetime, mock_template, mock_reports_dir):
        """Test generate Markdown report with template"""
        mock_reports_dir.mkdir = Mock()
        mock_template.exists.return_value = True
        mock_datetime.now.return_value.strftime.side_effect = ["20240101_120000", "2024-01-01 12:00:00", "2024-01-01"]
        
        mock_file.return_value.read.return_value = "Template content {{query}}"
        
        hosts = [{'ip': '192.168.1.1', 'port': 80}]
        result = generate_report(hosts, "vuln:CVE-2024-1234", 'markdown')
        
        assert result is not None
    
    @patch('argus_scan.REPORTS_DIR')
    @patch('argus_scan.TEMPLATE_FILE')
    @patch('argus_scan.datetime')
    @patch('builtins.open', new_callable=mock_open)
    @patch('argus_scan.console')
    def test_generate_report_markdown_no_template(self, mock_console, mock_file, mock_datetime, mock_template, mock_reports_dir):
        """Test generate Markdown report without template"""
        mock_reports_dir.mkdir = Mock()
        mock_template.exists.return_value = False
        mock_datetime.now.return_value.strftime.side_effect = ["20240101_120000", "2024-01-01 12:00:00"]
        
        hosts = [{'ip': '192.168.1.1', 'port': 80, 'hostnames': [], 'org': 'Test', 'isp': 'Test', 'product': 'Apache', 'version': '2.4', 'vulns': {}, 'shodan_link': 'http://test', 'direct_link': None, 'banner': 'test'}]
        result = generate_report(hosts, "test query", 'markdown')
        
        assert result is not None


class TestGenerateBasicMarkdown:
    """Tests for generate_basic_markdown function"""
    
    def test_generate_basic_markdown_with_cve(self):
        """Test generate basic markdown with CVE in query"""
        hosts = [
            {
                'ip': '192.168.1.1',
                'hostnames': ['test.com'],
                'port': 80,
                'org': 'Test Org',
                'isp': 'Test ISP',
                'product': 'Apache',
                'version': '2.4',
                'vulns': {'CVE-2024-1234': {}},
                'shodan_link': 'https://shodan.io/host/192.168.1.1',
                'direct_link': 'http://192.168.1.1:80',
                'banner': 'HTTP/1.1 200 OK'
            }
        ]
        
        result = generate_basic_markdown(hosts, "vuln:CVE-2024-1234")
        
        assert "CVE-2024-1234" in result
        assert "192.168.1.1" in result
        assert "Ethical Pentest" in result
    
    def test_generate_basic_markdown_no_cve(self):
        """Test generate basic markdown without CVE"""
        hosts = [
            {
                'ip': '192.168.1.1',
                'hostnames': [],
                'port': 80,
                'org': 'Test Org',
                'isp': 'Test ISP',
                'product': 'Apache',
                'version': '2.4',
                'vulns': {},
                'shodan_link': 'https://shodan.io/host/192.168.1.1',
                'direct_link': None,
                'banner': 'HTTP/1.1 200 OK'
            }
        ]
        
        result = generate_basic_markdown(hosts, "apache")
        
        assert "N/A" in result or "Ethical Pentest" in result
        assert "192.168.1.1" in result


class TestExportCSV:
    """Tests for export_csv function"""
    
    @patch('argus_scan.REPORTS_DIR')
    @patch('argus_scan.datetime')
    @patch('builtins.open', new_callable=mock_open)
    @patch('csv.writer')
    @patch('argus_scan.console')
    def test_export_csv(self, mock_console, mock_writer, mock_file, mock_datetime, mock_reports_dir):
        """Test CSV export"""
        mock_reports_dir.mkdir = Mock()
        mock_datetime.now.return_value.strftime.return_value = "20240101_120000"
        mock_writer_instance = Mock()
        mock_writer.return_value = mock_writer_instance
        
        hosts = [
            {
                'ip': '192.168.1.1',
                'hostnames': ['test.com'],
                'port': 80,
                'org': 'Test Org',
                'product': 'Apache',
                'version': '2.4',
                'vulns': {'CVE-2024-1234': {}},
                'shodan_link': 'https://shodan.io/host/192.168.1.1',
                'direct_link': 'http://192.168.1.1:80'
            }
        ]
        
        result = export_csv(hosts, "test query")
        
        assert result is not None
        mock_writer_instance.writerow.assert_called()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

