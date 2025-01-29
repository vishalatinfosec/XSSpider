import os
import argparse
import logging
import time
import urllib3
import signal
import sys
import json
import glob
import resource
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from colorama import Fore, init
from requests.exceptions import RequestException

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("WDM").setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

vulnerable_urls = []
scan_running = True
output_format = "html"

def cleanup_core_dumps():
    for core_file in glob.glob("core.*"):
        os.remove(core_file)

def load_payloads(payload_file):
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading payloads: {e}")
        sys.exit(1)

def generate_payload_urls(url, payload):
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    return [urlunsplit((scheme, netloc, path, urlencode({**query_params, key: [payload]}, doseq=True), fragment)) for key in query_params]

def create_driver():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    return webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)

def check_vulnerability(url, payload, timeout, retries=3):
    if not scan_running:
        return None
    driver = create_driver()
    try:
        for payload_url in generate_payload_urls(url, payload):
            if not scan_running:
                break
            for attempt in range(retries):
                try:
                    driver.get(payload_url)
                    try:
                        alert = WebDriverWait(driver, timeout).until(EC.alert_is_present())
                        if alert.text:
                            print(Fore.GREEN + f"[✓] Vulnerable: {payload_url}")
                            alert.accept()
                            vulnerable_urls.append(payload_url)
                            return payload_url
                    except TimeoutException:
                        print(Fore.RED + f"[✗] Not Vulnerable: {payload_url}")
                    break
                except (WebDriverException, RequestException):
                    print(Fore.YELLOW + f"[!] Retrying ({attempt+1}/{retries})...")
                    time.sleep(2 ** attempt)
    finally:
        driver.quit()
    return None

def save_results():
    if not vulnerable_urls:
        print(Fore.YELLOW + "[!] No vulnerabilities found. No report generated.")
        return
    filename = f"xssresult.{output_format}"
    with open(filename, "w") as file:
        if output_format == "json":
            json.dump(vulnerable_urls, file, indent=4)
        elif output_format == "txt":
            file.write("\n".join(vulnerable_urls))
        elif output_format == "html":
            file.write("<html><head><title>XSS Scan Report</title></head><body><h2>XSS Vulnerability Report</h2><ul>" + "".join(f'<li><a href="{url}" target="_blank">{url}</a></li>' for url in vulnerable_urls) + "</ul></body></html>")
    print(Fore.GREEN + f"[✓] Results saved as {filename}")

def signal_handler(sig, frame):
    global scan_running
    if scan_running:
        scan_running = False
        print(Fore.YELLOW + "\n[!] Scan interrupted. Saving results...")
        save_results()
        cleanup_core_dumps()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def run_scan(urls, payload_file, timeout):
    payloads = load_payloads(payload_file)
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_vulnerability, url, payload, timeout) for url in urls for payload in payloads]
            for future in as_completed(futures):
                if not scan_running:
                    break
                future.result()
    except Exception as e:
        print(Fore.RED + f"[!] Error during scanning: {e}")

def main():
    global output_format
    parser = argparse.ArgumentParser(description="XSS Scanner CLI")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs to scan")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout for each request (default: 0.5s)")
    parser.add_argument("-o", "--output", choices=["json", "html", "txt"], help="Output format (json, html, txt)")
    args = parser.parse_args()

    if args.output:
        output_format = args.output
    urls = ([args.url] if args.url else []) + (open(args.list).read().splitlines() if args.list and os.path.isfile(args.list) else [])
    if not urls:
        print(Fore.RED + "[!] No URLs provided.")
        sys.exit(1)
    
    print(Fore.CYAN + "[i] Starting XSS Scan...")
    start_time = time.time()
    run_scan(urls, args.payloads, args.timeout)
    cleanup_core_dumps()
    print(Fore.YELLOW + f"[i] Scanning finished in {int(time.time() - start_time)} seconds.")
    print(Fore.GREEN + f"[✓] Total Vulnerable URLs Found: {len(vulnerable_urls)}")
    save_results()

if __name__ == "__main__":
    main()
