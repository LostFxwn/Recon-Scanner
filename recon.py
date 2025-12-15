import argparse
import socket
import sys
import concurrent.futures
import requests
import re
import json
import csv
import ssl
import logging
import base64
import time
import os
from datetime import datetime
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

def parse_ports(port_arg):
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            for p in range(int(start), int(end) + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)

def read_targets(target_path):
    targets = []
    try:
        with open(target_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        print(f"Error: Could not find file {target_path}")
        sys.exit(1)
    return targets

def load_previous_results(output_prefix):
    json_filename = f"{output_prefix}.results.json"
    if not os.path.exists(json_filename):
        return None
    try:
        with open(json_filename, 'r') as f:
            data = json.load(f)
        print(f"[+] Loaded previous results from {json_filename}")
        return data
    except Exception as e:
        logger.error(f"Error loading previous results: {e}", exc_info=True)
        return None

def get_scanned_targets(previous_results):
    scanned = set()
    if not previous_results or "targets" not in previous_results:
        return scanned
    for host, host_data in previous_results["targets"].items():
        for port_str in host_data.get("ports", {}).keys():
            scanned.add((host, int(port_str)))
    return scanned

def scan_target(target, port, timeout, retry_count=1, retry_delay=1):
    attempt = 0
    last_error = None
    while attempt < retry_count:
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner_bytes = sock.recv(4096)
                banner_decoded = banner_bytes.decode('utf-8', errors='ignore').strip()
                banner_b64 = base64.b64encode(banner_bytes).decode('utf-8')
                return {
                    "host": target,
                    "port": port,
                    "banner": banner_decoded if banner_decoded else "No banner",
                    "banner_b64": banner_b64,
                    "scanned_at": datetime.utcnow().isoformat() + 'Z'
                }
        except socket.timeout:
            last_error = {
                "host": target,
                "port": port,
                "status": "filtered",
                "error": "Connection timed out",
                "scanned_at": datetime.utcnow().isoformat() + 'Z'
            }
        except ConnectionRefusedError:
            return {
                "host": target,
                "port": port,
                "status": "closed",
                "error": "Connection refused",
                "scanned_at": datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            last_error = {
                "host": target,
                "port": port,
                "status": "unknown",
                "error": str(e),
                "scanned_at": datetime.utcnow().isoformat() + 'Z'
            }
        attempt += 1
        if attempt < retry_count:
            backoff_time = (2 ** (attempt - 1)) * retry_delay
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Retry {attempt}/{retry_count-1} for {target}:{port} after {backoff_time}s")
            time.sleep(backoff_time)
    if last_error:
        logger.error(f"Scan of {target}:{port} failed after {retry_count} attempt(s)")
        return last_error
    return {
        "host": target,
        "port": port,
        "status": "unknown",
        "error": "Unknown error",
        "scanned_at": datetime.utcnow().isoformat() + 'Z'
    }

def probe_http(target, port, timeout, args):
    http_data = {}
    fingerprint_tags = []
    if not (args.http or port in [80, 443, 8080, 8443]):
        return None
    requests.packages.urllib3.disable_warnings()
    for scheme in ['http', 'https']:
        if scheme == 'https' and port not in [443, 8443]:
            continue
        base_url = f"{scheme}://{target}:{port}"
        try:
            response = requests.get(base_url, timeout=timeout, allow_redirects=True, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            http_data['url'] = base_url
            http_data['status_code'] = response.status_code
            http_data['final_url'] = response.url
            server_header = response.headers.get('Server', 'N/A')
            http_data['server_header'] = server_header
            if 'Apache' in server_header:
                fingerprint_tags.append("Apache")
            if 'nginx' in server_header:
                fingerprint_tags.append("Nginx")
            if 'IIS' in server_header:
                fingerprint_tags.append("IIS")
            if 'cloudflare' in server_header:
                fingerprint_tags.append("Cloudflare")
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            http_data['title'] = title_match.group(1).strip() if title_match else "No Title"
            meta_desc_match = re.search(r'<meta\s+name=["\']?description["\']?\s+content=["\']?(.*?)["\']?[>\s]', response.text, re.IGNORECASE)
            http_data['meta_description'] = meta_desc_match.group(1).strip() if meta_desc_match else "N/A"
            cookies = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else []
            http_data['cookies'] = cookies[:5] if cookies else []
            http_data['response_sample'] = response.text[:4096] if response.text else ""
            try:
                robots = requests.get(f"{base_url}/robots.txt", timeout=timeout, verify=False)
                if robots.status_code == 200:
                    fingerprint_tags.append("robots.txt")
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    logger.debug(f"robots.txt probe failed: {e}")
            try:
                sitemap = requests.get(f"{base_url}/sitemap.xml", timeout=timeout, verify=False)
                if sitemap.status_code == 200:
                    fingerprint_tags.append("sitemap.xml")
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    logger.debug(f"sitemap.xml probe failed: {e}")
            try:
                wp = requests.get(f"{base_url}/wp-login.php", timeout=timeout, verify=False)
                if wp.status_code == 200 and "user_login" in wp.text:
                    fingerprint_tags.append("WordPress")
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    logger.debug(f"wp-login.php probe failed: {e}")
            try:
                xmlrpc = requests.get(f"{base_url}/xmlrpc.php", timeout=timeout, verify=False)
                if xmlrpc.status_code == 200:
                    fingerprint_tags.append("WordPress-XMLRPC")
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    logger.debug(f"xmlrpc.php probe failed: {e}")
            try:
                favicon = requests.get(f"{base_url}/favicon.ico", timeout=timeout, verify=False)
                if favicon.status_code == 200:
                    favicon_hash = hashlib.sha256(favicon.content).hexdigest()
                    http_data['favicon_sha256'] = favicon_hash
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    logger.debug(f"favicon.ico probe failed: {e}")
            if 'X-Sucuri-ID' in response.headers:
                fingerprint_tags.append("Sucuri-WAF")
            if 'X-Mod-Security' in response.headers:
                fingerprint_tags.append("ModSecurity-WAF")
            http_data['fingerprint'] = fingerprint_tags
            return http_data
        except requests.exceptions.RequestException as e:
            if args.verbose:
                logger.debug(f"HTTP probe failed for {base_url}: {e}")
            continue
    return None

def probe_tls(target, port, timeout, args):
    tls_data = {}
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                tls_data['subject_cn'] = subject.get('commonName', 'N/A')
                tls_data['issuer_cn'] = issuer.get('commonName', 'N/A')
                tls_data['notBefore'] = cert.get('notBefore', 'N/A')
                tls_data['notAfter'] = cert.get('notAfter', 'N/A')
                date_fmt = '%b %d %H:%M:%S %Y %Z'
                try:
                    expire_date = datetime.strptime(cert['notAfter'], date_fmt)
                    is_expired = datetime.utcnow() > expire_date
                    tls_data['expired'] = is_expired
                except (ValueError, KeyError):
                    tls_data['expired'] = "Unknown"
                tls_data['serialNumber'] = cert.get('serialNumber', 'N/A')
                tls_data['version'] = cert.get('version', 'N/A')
                return tls_data
    except ssl.SSLError as e:
        logger.error(f"SSL Error for {target}:{port}: {e}")
        return {"error": f"SSL Error: {e}"}
    except Exception as e:
        logger.error(f"TLS Connection Error for {target}:{port}: {e}")
        return {"error": f"TLS Connection Error: {e}"}

def save_results(structured_results, prefix, args, resumed=False):
    if not prefix:
        return
    json_filename = f"{prefix}.results.json"
    meta = {
        "run_started": datetime.utcnow().isoformat() + 'Z',
        "args": vars(args),
        "resumed": resumed
    }
    final_json = {
        "meta": meta,
        "targets": structured_results["targets"]
    }
    try:
        with open(json_filename, 'w') as f:
            json.dump(final_json, f, indent=2)
        print(f"[+] JSON results saved to {json_filename}")
    except Exception as e:
        logger.error(f"Error saving JSON: {e}", exc_info=True)
    
    csv_filename = f"{prefix}.results.csv"
    fieldnames = ['host', 'port', 'status', 'service_hint', 'http_status', 'http_title', 'server_header', 'fingerprint_tags', 'cert_subject_cn', 'cert_notAfter', 'banner_snippet']
    csv_rows = []
    
    for host, host_data in structured_results["targets"].items():
        for port_str, port_data in host_data["ports"].items():
            row = {
                'host': host,
                'port': port_str,
                'status': port_data.get('status', 'N/A'),
                'service_hint': port_data.get('service_hint', 'tcp'),
                'banner_snippet': port_data.get('banner', '')[:50].replace('\n', ' ')
            }
            
            http_data = port_data.get('http', {})
            row['http_status'] = http_data.get('status_code', '')
            row['http_title'] = http_data.get('title', '')
            row['server_header'] = http_data.get('server_header', '')
            tags = http_data.get('fingerprint', [])
            row['fingerprint_tags'] = ", ".join(tags) if tags else ''
            
            tls_data = port_data.get('tls', {})
            row['cert_subject_cn'] = tls_data.get('subject_cn', '')
            row['cert_notAfter'] = tls_data.get('notAfter', '')
            csv_rows.append(row)
    
    try:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"[+] CSV results saved to {csv_filename}")
    except Exception as e:
        logger.error(f"Error saving CSV: {e}", exc_info=True)

def scanner_engine(targets, ports, args, skip_targets=None):
    workers = args.workers
    timeout = args.timeout
    retry_count = args.retry
    retry_delay = 1.0
    json_output = {"targets": {}}
    
    if skip_targets is None:
        skip_targets = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_scan = {}
        for target in targets:
            for port in ports:
                if (target, port) not in skip_targets:
                    future = executor.submit(scan_target, target, port, timeout, retry_count, retry_delay)
                    future_to_scan[future] = (target, port)
        
        for future in concurrent.futures.as_completed(future_to_scan):
            target, port = future_to_scan[future]
            port_str = str(port)
            if target not in json_output["targets"]:
                json_output["targets"][target] = {"ports": {}}
            
            try:
                result = future.result()
                if "error" in result and result.get("status") in ["closed", "filtered"]:
                    port_result = {
                        "status": result.get("status", "unknown"),
                        "error": result.get("error"),
                        "scanned_at": result.get("scanned_at")
                    }
                    json_output["targets"][target]["ports"][port_str] = port_result
                    if args.verbose:
                        logger.debug(f"[{result['status'].upper()}] {target}:{port} - {result['error']}")
                    continue
                
                port_result = {
                    "status": "open",
                    "banner": result.get('banner', 'N/A'),
                    "service_hint": "tcp",
                    "scanned_at": result.get("scanned_at")
                }
                
                if args.http or port in [80, 443, 8080, 8443]:
                    http_result = probe_http(target, port, timeout, args)
                    if http_result:
                        port_result['http'] = http_result
                        port_result['service_hint'] = "http"
                        print(f"[HTTP] {target}:{port} - Status: {http_result['status_code']}")
                
                if args.tls or port in [443, 8443]:
                    tls_result = probe_tls(target, port, timeout, args)
                    if tls_result and 'error' not in tls_result:
                        port_result['tls'] = tls_result
                        port_result['service_hint'] = "https"
                        print(f"[TLS] {target}:{port} - CN: {tls_result.get('subject_cn')}")
                    elif tls_result:
                        port_result['tls'] = tls_result
                        if args.verbose:
                            logger.debug(f"[TLS ERROR] {target}:{port}")
                
                json_output["targets"][target]["ports"][port_str] = port_result
                print(f"[OPEN] {target}:{port} - Service: {port_result['service_hint']}")
                
            except Exception as e:
                logger.error(f"Worker Exception on {target}:{port}: {e}", exc_info=True)
    
    return json_output

def parse_args():
    parser = argparse.ArgumentParser(description="Python Recon Tool")
    parser.add_argument("--targets", required=True, help="Path to file with IPs (one per line)")
    parser.add_argument("--ports", required=True, help="Ports e.g. 80,443,8000-8100")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent workers (default 20)")
    parser.add_argument("--http", action="store_true", help="Probe HTTP services")
    parser.add_argument("--tls", action="store_true", help="Probe TLS services")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds (default 5.0)")
    parser.add_argument("--output", help="Output file prefix")
    parser.add_argument("--retry", type=int, default=1, help="Retry transient failures (default 1, no retry)")
    parser.add_argument("--resume", action="store_true", help="Resume from previous scan; skip already-scanned targets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    
    print(f"[*] Loading targets from {args.targets}...")
    target_list = read_targets(args.targets)
    
    if not target_list:
        print("[!] No targets loaded. Exiting.")
        sys.exit(1)
    
    print(f"[*] Parsing port list...")
    port_list = parse_ports(args.ports)
    
    if not port_list:
        print("[!] No ports parsed. Exiting.")
        sys.exit(1)
    
    skip_targets = set()
    resumed = False
    if args.resume and args.output:
        previous_results = load_previous_results(args.output)
        if previous_results:
            skip_targets = get_scanned_targets(previous_results)
            resumed = True
            print(f"[*] Resuming scan: skipping {len(skip_targets)} already-scanned (host:port) pairs")
    
    print(f"[*] Starting concurrent scan with {args.workers} workers...")
    if args.retry > 1:
        print(f"[*] Retry enabled: up to {args.retry} attempts per port with exponential backoff")
    
    structured_results = scanner_engine(target_list, port_list, args, skip_targets)
    open_port_count = sum(len(host["ports"]) for host in structured_results["targets"].values())
    
    print("\n --- CONFIG ---")
    print(f"Targets: {len(target_list)} hosts loaded")
    print(f"Ports: {len(port_list)} ports to scan per host")
    print(f"Workers: {args.workers}")
    print(f"Retry count: {args.retry}")
    print(f"Resumed: {resumed}")
    total_ops = (len(target_list) * len(port_list)) - len(skip_targets)
    print(f"Total Ops: {total_ops} checks to perform ({len(skip_targets)} skipped)")
    print(f"Found {open_port_count} open services")
    
    if args.output:
        print(f"[*] Saving results to {args.output} files...")
        save_results(structured_results, args.output, args, resumed=resumed)
    else:
        print("[!] No output prefix provided. Results not saved to file.")
    print("---------------\n")

if __name__ == "__main__":
    def scan_target(target, port, timeout, retry_count=1, retry_delay=1):
        attempt = 0
        last_error = None
        
        while attempt < retry_count:
            try:
                with socket.create_connection((target, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    try:
                        banner_bytes = sock.recv(4096)
                    except socket.timeout:
                        banner_bytes = b''
                    
                    banner_decoded = banner_bytes.decode('utf-8', errors='ignore').strip()
                    banner_b64 = base64.b64encode(banner_bytes).decode('utf-8')
                    return {
                        "host": target,
                        "port": port,
                        "banner": banner_decoded if banner_decoded else "No banner",
                        "banner_b64": banner_b64,
                        "scanned_at": datetime.utcnow().isoformat() + 'Z'
                    }
            except ConnectionRefusedError:
                return {
                    "host": target,
                    "port": port,
                    "status": "closed",
                    "error": "Connection refused",
                    "scanned_at": datetime.utcnow().isoformat() + 'Z'
                }
            except Exception as e:
                last_error = {
                    "host": target,
                    "port": port,
                    "status": "unknown",
                    "error": str(e),
                    "scanned_at": datetime.utcnow().isoformat() + 'Z'
                }
            
            attempt += 1
            if attempt < retry_count:
                backoff_time = (2 ** (attempt - 1)) * retry_delay
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Retry {attempt}/{retry_count-1} for {target}:{port} after {backoff_time}s")
                time.sleep(backoff_time)
        
        if last_error:
            logger.error(f"Scan of {target}:{port} failed after {retry_count} attempt(s)")
            return last_error
        
        return {
            "host": target,
            "port": port,
            "status": "unknown",
            "error": "Unknown error",
            "scanned_at": datetime.utcnow().isoformat() + 'Z'
        }
    main()