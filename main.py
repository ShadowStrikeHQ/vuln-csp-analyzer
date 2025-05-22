import argparse
import requests
import logging
import re
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common CSP bypass techniques
CSP_BYPASSES = {
    "script_src": [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "https:",
        "*",
        "example.com", # add potential vulnerable domains
        "//example.com",
        "https://example.com"
    ],
    "object-src": [
        "'none'", # can lead to issues in older browsers
        "data:",
        "*",
    ],
    "base-uri": [
        "*",
    ],
    "default-src": [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "*",
        "https:",
    ],
    "report-uri": [
        # missing/weak report-uri
    ],
    "frame-ancestors": [
        "*",
        "none",
    ]
}

# Define directives that are often missing
MISSING_DIRECTIVES = [
    "frame-ancestors",
    "object-src",
    "base-uri",
    "require-sri-for script style",
    "upgrade-insecure-requests",
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyzes Content Security Policy (CSP) headers for weaknesses.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser

def fetch_csp_header(url):
    """
    Fetches the CSP header from a given URL.
    
    Args:
        url (str): The URL to fetch the CSP header from.
    
    Returns:
        str: The CSP header value, or None if not found.
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.headers.get("Content-Security-Policy") or response.headers.get("X-Content-Security-Policy") or response.headers.get("Content-Security-Policy-Report-Only")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None

def analyze_csp(csp_header):
    """
    Analyzes a CSP header for weaknesses and suggests improvements.
    
    Args:
        csp_header (str): The CSP header value.
    
    Returns:
        list: A list of findings (strings).
    """
    findings = []
    if not csp_header:
        findings.append("CSP header is missing. This is a major security vulnerability.")
        return findings # Exit early if no CSP
        
    directives = {}
    for directive in csp_header.split(';'):
        directive = directive.strip()
        if not directive:
            continue # skip empty directives.
        
        parts = directive.split(' ', 1) # Split on first space to separate directive and values.
        directive_name = parts[0].strip()
        directive_value = parts[1].strip() if len(parts) > 1 else ""
        
        directives[directive_name] = directive_value.split(' ') # Store values in list format
    
    # Check for common bypasses in script-src
    if "script-src" in directives:
        for bypass in CSP_BYPASSES["script_src"]:
            if bypass in directives["script-src"]:
                findings.append(f"script-src allows {bypass}. This is a potential bypass.")
    else:
        findings.append("script-src is missing, potentially allowing arbitrary script execution.")

    # Check for common bypasses in object-src
    if "object-src" in directives:
        for bypass in CSP_BYPASSES["object-src"]:
            if bypass in directives["object-src"]:
                findings.append(f"object-src allows {bypass}. This is a potential bypass.")
    else:
        findings.append("object-src is missing, potentially allowing arbitrary object execution.")

    # Check for common bypasses in base-uri
    if "base-uri" in directives:
        for bypass in CSP_BYPASSES["base-uri"]:
            if bypass in directives["base-uri"]:
                findings.append(f"base-uri allows {bypass}. This may lead to XSS or other issues.")
    else:
        findings.append("base-uri is missing, which may lead to XSS.")
    
    if "default-src" in directives:
        for bypass in CSP_BYPASSES["default-src"]:
            if bypass in directives["default-src"]:
                findings.append(f"default-src allows {bypass}.  This could negate other more restrictive directives.")
    else:
        findings.append("default-src is missing, which can lead to vulnerabilities.")

    if "frame-ancestors" in directives:
        for bypass in CSP_BYPASSES["frame-ancestors"]:
            if bypass == '*':
              findings.append(f"frame-ancestors allows {bypass}. Clickjacking can be performed.")
            if bypass == 'none':
              findings.append(f"frame-ancestors allows {bypass}. No framing is allowed.")
    else:
        findings.append("frame-ancestors is missing, clickjacking can be performed.")
    
    if 'report-uri' not in directives and 'report-to' not in directives:
        findings.append("Neither report-uri nor report-to are present.  Violation reports will not be generated, so vulnerabilities cannot be detected automatically.")

    for directive in MISSING_DIRECTIVES:
      if directive not in directives:
        findings.append(f"{directive} is missing. Consider adding it for enhanced security.")

    return findings

def validate_url(url):
    """
    Validates that the provided URL is properly formatted.
    
    Args:
        url (str): The URL to validate.
    
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def main():
    """
    Main function to execute the CSP analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not validate_url(url):
        logging.error("Invalid URL. Please provide a valid URL (e.g., https://example.com).")
        sys.exit(1)

    csp_header = fetch_csp_header(url)

    if csp_header:
        logging.info(f"CSP Header: {csp_header}")
        findings = analyze_csp(csp_header)

        if findings:
            print("Vulnerabilities found:")
            for finding in findings:
                print(f"- {finding}")
        else:
            print("No vulnerabilities found.")
    else:
        print("No CSP header found in the response.")
        print("The website may be vulnerable.")


if __name__ == "__main__":
    main()