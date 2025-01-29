# XSSpider

A powerful and efficient Python-based command-line tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. This tool automates the process of injecting XSS payloads into target URLs and identifies vulnerabilities by monitoring for alert pop-ups. Built with Selenium and multi-threading support, it is ideal for both security professionals and developers looking to secure their web applications.

## Features
- **Multi-URL Scanning**: Scan a single URL or a list of URLs from a file.
- **Custom Payloads**: Use a file containing custom XSS payloads for testing.
- **Concurrent Scanning**: Utilizes multi-threading for faster scanning.
- **Output Formats**: Save results in `JSON`, `HTML`, or `TXT` format.
- **Headless Mode**: Runs in a headless Chrome browser for efficiency.

## Prerequisites

Before using this tool, ensure you have the following installed:

- Python 3.x
- Chrome browser
- ChromeDriver
- The following Python packages:
  - `selenium`
  - `webdriver-manager`
  - `colorama`
  - `requests`
  - `urllib3`


## Installation

### Clone the repository

```bash
https://github.com/vishalatinfosec/XSSpider/XSSpider.git
```
```bash
cd XSSpider
```

### Install the requirements

```bash
pip install selenium webdriver-manager colorama requests urllib3
```

### Chrome Installation

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

- If you encounter any errors during installation, use the following command:

```bash
sudo apt -f install
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```


### Chrome Driver Installation

```bash
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
```
```bash
unzip chromedriver-linux64.zip
```
```bash
cd chromedriver-linux64 
```
```bash
sudo mv chromedriver /usr/bin
```

---

## Usage

### Run the Script

```bash
python3 XSSpider.py -u <URL> -p <payloads.txt> [-t <timeout>] [-o <output_format>]
```

---

## Options

| Option | Description | Default |
|---|---|---|
| `-u`, `--url` | Single URL to scan. | None |
| `-l`, `--list` | File containing list of URLs to scan (one URL per line). | None |
| `-p`, `--payloads` | Path to a file containing XSS payloads (one payload per line). | None |
| `-t`, `--timeout` | Timeout for each request (in seconds). | `0.5` |
| `-o`, `--output` | Output format for results (`json`, `html`, or `txt`). | `html` |
| `-h`, `--help` | Show help message and usage instructions. | N/A |

---

## Examples
### Basic Usage

1. To scan a single URL:

```bash
python XSSpider.py -u http://example.com?q=test -p ./payloads/xss.txt -o html
```

2. To scan a list of URLs from a file:

```bash
python XSSpider.py -l urls.txt -p ./payloads/xss.txt -o json
```

3. To specify a custom timeout:

```bash
python XSSpider.py -u http://example.com?q=test -p ./payloads/xss.txt -t 0.5 -o txt
```

---

### Why Use This Tool?
- **Efficiency:** Automates the tedious process of manual XSS testing.
- **Customizability:** Use your own payloads to target specific vulnerabilities.
- **Scalability:** Scan multiple URLs concurrently for large-scale testing.
- **User-Friendly:** Simple CLI interface with clear output formats.

### Notes

- **Ensure that you have the appropriate permissions to scan the URLs.**
- **This tool is intended for ethical use only, such as during authorized penetration tests or bug bounty programs.**

---

#### License
Copyright (C) Vishal (vishalatinfosec@gmail.com)

This tool is open-source and released under the MIT License. Feel free to fork or contribute.

---

#### Author
Developed by [Vishal].

---

### Contributing
Contributions, feature requests, and bug reports are welcome! Submit a pull request or open an issue.

---
