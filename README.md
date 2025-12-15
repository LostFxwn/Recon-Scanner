# ReconTool - Python Reconnaissance Scanner
I originally made this as a uni project and though that it was cool enough to keep on here for future referece. 

A concurrent, multi-threaded network reconnaissance tool for port scanning, HTTP service detection, and TLS certificate analysis. ReconTool helps security researchers and network administrators discover open ports, identify web services, and extract certificate information from target hosts at scale.

## Project Overview

**ReconTool** is a Python-based reconnaissance utility designed to scan multiple targets across specified ports with advanced service detection capabilities. Unlike traditional port scanners, ReconTool combines basic port scanning with intelligent HTTP fingerprinting (detecting web servers, WordPress installations, WAF signatures) and TLS certificate extraction.

### Key Capabilities

- **Concurrent Port Scanning**: Fast multi-threaded scanning using Python's `concurrent.futures`
- **HTTP Service Probing**: Automatic detection of HTTP/HTTPS services with fingerprinting
- **TLS/SSL Certificate Analysis**: Extract and validate SSL/TLS certificate information
- **Service Detection**: Identify web server types, CMS platforms, WAF systems, and web technologies
- **Resume Support**: Pause and resume scans without re-scanning already-completed targets
- **Flexible Output**: Results exported in both JSON and CSV formats for easy analysis
- **Retry Logic**: Exponential backoff retry mechanism for transient failures

## Requirements

### System Requirements

- Python 3.6 or higher
- Windows, macOS, or Linux

### Python Libraries

To run ReconTool, install the following dependencies:

### Standard Library

ReconTool uses the following built-in Python modules:

- `socket` - Low-level network socket operations
- `ssl` - SSL/TLS certificate handling
- `concurrent.futures` - Thread pool management
- `argparse` - Command-line argument parsing
- `json` - JSON output handling
- `csv` - CSV export functionality
- `re` - Regular expression matching for HTML parsing
- `datetime` - Timestamp generation
- `logging` - Debug and error logging
- `base64` - Banner encoding
- `hashlib` - Favicon hashing

## Running the Code

### Basic Usage

1. **Prepare a targets file** (`targets.txt`):
2. **Run the scanner** (python recon.py --targets targets.txt --ports 80,443)

### Command-Line Arguments
--targets FILE              (Required) Path to file containing target hosts (one per line) --ports PORTS              (Required) Ports to scan (e.g., 80,443,8000-8100) --workers NUM              Number of concurrent worker threads (default: 20) --http                     Enable HTTP probing and fingerprinting --tls                      Enable TLS certificate extraction --timeout SECONDS          Socket/HTTP timeout in seconds (default: 5.0) --output PREFIX            Output file prefix for saving results (.json and .csv) --retry NUM                Number of retry attempts for failed scans (default: 1, no retry) --resume                   Resume from previous scan (skips already-scanned host:port pairs) --verbose, -v              Enable verbose/debug logging

### Usage Examples

**Scan ports 80 and 443 with HTTP probing:** (python recon.py --targets targets.txt --ports 80,443 --http --output results)
**Scan a port range with TLS and HTTP probing:** (python recon.py --targets targets.txt --ports 80,443,8000-8100 --http --tls --workers 50 --output results)
**Resume a previous scan:** (python recon.py --targets targets.txt --ports 80,443 --http --output results --resume)
**Enable retries with debug logging:** (python recon.py --targets targets.txt --ports 22,80,443 --http --retry 3 --verbose --output results)

## Features Implemented

### 1. **Port Scanning**
- Establishes TCP connections to target hosts on specified ports
- Attempts to receive banner data from open ports
- Handles three port states: `open`, `closed`, `filtered`
- Supports individual ports and port ranges (e.g., `8000-8100`)

### 2. **HTTP Service Detection & Fingerprinting**
- Probes both HTTP and HTTPS protocols
- Extracts HTTP status codes and response headers
- Parses HTML titles and meta descriptions
- Identifies web servers: Apache, Nginx, IIS, Cloudflare
- **CMS Detection**: Detects WordPress installations via `/wp-login.php`
- **WAF Detection**: Identifies Sucuri and ModSecurity WAF signatures
- **Additional Probes**: Checks for `/robots.txt`, `/sitemap.xml`, `/favicon.ico`
- **Favicon Hashing**: Calculates SHA-256 hash of favicon for identification
- **XMLRPC Detection**: Identifies WordPress XML-RPC endpoints

### 3. **TLS/SSL Certificate Analysis**
- Extracts certificate subject and issuer common names
- Validates certificate expiration dates
- Captures serial numbers and certificate versions
- Handles SSL/TLS errors gracefully with detailed error reporting

### 4. **Concurrency & Performance**
- Multi-threaded scanning with configurable worker pool (default: 20 threads)
- `concurrent.futures.ThreadPoolExecutor` for efficient resource management
- Non-blocking asynchronous result processing

### 5. **Retry Logic**
- Configurable retry attempts for transient connection failures
- **Exponential Backoff**: Retry delays increase exponentially (1s, 2s, 4s, etc.)
- Applies to socket timeouts and connection errors

### 6. **Resume Capability**
- Loads previous results from JSON files
- Tracks already-scanned (host, port) pairs
- Skips completed scans when `--resume` flag is used
- Allows resuming interrupted scans without wasting time

### 7. **Output Formats**

**JSON Output** (`.results.json`): { "meta": { "run_started": "ISO8601 timestamp", "args": { ... }, "resumed": boolean }, "targets": { "host": { "ports": { "80": { "status": "open", "banner": "...", "http": { ... }, "tls": { ... } } } } } }
**CSV Output** (`.results.csv`):
- Flattened results with columns: host, port, status, service_hint, http_status, http_title, server_header, fingerprint_tags, cert_subject_cn, cert_notAfter, banner_snippet

### 8. **Logging & Error Handling**
- Configurable logging levels (INFO, DEBUG, WARNING)
- Detailed error messages for debugging
- Graceful handling of network timeouts and SSL errors
- Verbose mode for comprehensive diagnostic information

## Reflection on Project

### Challenges Encountered

1. **HTTP Banner Collection**: Initial difficulty with grabbing HTTP response banners before timeout. Solved by implementing a short socket timeout window during banner capture.

2. **Concurrent Threading Complexity**: Managing thread safety across multiple workers scanning simultaneously required careful consideration of result aggregation and data structure integrity.

3. **TLS Certificate Parsing**: SSL handshake failures and self-signed certificates required explicit error handling without breaking the scanning workflow.

4. **Resume Logic**: Tracking scanned (host, port) pairs across resumed runs needed careful JSON parsing and duplicate detection.

5. **Port Range Parsing**: Implementing flexible port specification (e.g., "80,443,8000-8100") required iterative range parsing logic.

6. **HTML Parsing**: Using regex for title/meta extraction instead of a proper HTML parser to minimize dependencies, though regex fragility was a concern.

### Learning Outcomes

- **Concurrency Patterns**: Gained deep understanding of Python's ThreadPoolExecutor and concurrent.futures
- **Network Programming**: Improved knowledge of socket operations, SSL/TLS handshakes, and HTTP protocol details
- **HTTP Fingerprinting**: Learned practical web server identification through header analysis and endpoint probing
- **Error Resilience**: Developed strategies for handling network-level failures gracefully
- **Code Organization**: Structured modular functions for separation of concerns (scanning, probing, saving)

### What Went Well

- Clean command-line interface with argparse
- Efficient concurrent execution with configurable parallelism
- Comprehensive output formats supporting both structured (JSON) and tabular (CSV) data
- Flexible port specification supporting ranges and lists
- Resume functionality enabling long-running scans to be paused and continued

### Areas for Improvement

1. **Banner Grabbing**: Currently only receives initial socket data. Could implement protocol-specific banner probes (SSH, FTP, SMTP, etc.).

2. **Service Detection**: Could integrate with existing service signatures (e.g., nmap service probes) or machine learning models for better accuracy.

3. **HTML Parsing**: Replace regex with proper HTML parsing library (`BeautifulSoup`) for more reliable extraction.

4. **IPv6 Support**: Current implementation only handles IPv4. Adding IPv6 would expand applicability.

5. **Rate Limiting**: Could implement adaptive rate limiting to avoid overwhelming target systems.

6. **DNS Resolution**: Optional DNS resolution and reverse DNS lookups for better host identification.

7. **Proxy Support**: Adding proxy support for scanning through SOCKS5 or HTTP proxies.

8. **Progress Indicators**: Real-time progress bar showing scan completion percentage.

9. **Timeout Optimization**: Could implement adaptive timeouts based on network latency.

10. **Plugin Architecture**: Modular probe system allowing custom fingerprinting plugins.

### Technical Debt

- The `scan_target` function is duplicated in the `__main__` block and should be refactored to avoid redundancy
- Consider moving configuration to a YAML/INI file instead of command-line arguments for large-scale scans
- Add unit tests for core functions (port parsing, result aggregation, etc.)

## Conclusion

ReconTool demonstrates practical application of Python's concurrency model for network reconnaissance. While designed as an educational exercise, it provides a solid foundation for network scanning workflows and could serve as a template for more sophisticated security tools. Future enhancements would focus on service detection accuracy, protocol diversity, and enterprise-scale functionality.

---

**Author**: Eilis G  
**Repository**: [EilishG-SETU/ReconTool](https://github.com/EilishG-SETU/ReconTool)  
**Last Updated**: December 15, 2025