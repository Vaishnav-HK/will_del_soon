import requests
from database.db_manager import add_vulnerability, clear_vulnerabilities

def run_dast_scan(url, asset_id):
    """
    Executes lightweight Dynamic Application Security Testing (DAST) on the URL.
    Returns (success_boolean, list_of_findings_or_error_message)
    """
    findings = []
    
    try:
        # Clear old scan results before running a new active scan
        clear_vulnerabilities(asset_id)
        # Check 1: Security Headers
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        missing_headers = []
        if 'Content-Security-Policy' not in headers:
            missing_headers.append('Content-Security-Policy')
        if 'X-Frame-Options' not in headers:
            missing_headers.append('X-Frame-Options')
        if 'Strict-Transport-Security' not in headers:
            missing_headers.append('Strict-Transport-Security')
            
        if missing_headers:
            desc = f"Missing modern security barriers: {', '.join(missing_headers)}"
            add_vulnerability(asset_id, 'Medium', 'Missing Security Headers', desc)
            findings.append(('Medium', 'Missing Security Headers', desc))
            
        # Check 2: Basic Injection Check (XSS)
        # We append a safe XSS payload to a generic query parameter to see if it reflects
        xss_payload = "<script>console.log('xss_test')</script>"
        test_url = f"{url}?q={xss_payload}&search={xss_payload}&id={xss_payload}"
        
        inj_response = requests.get(test_url, timeout=10)
        
        if xss_payload in inj_response.text:
            desc = f"Reflective XSS suspected. Payload '{xss_payload}' was reflected unsanitized in the response."
            add_vulnerability(asset_id, 'High', 'Reflective XSS', desc)
            findings.append(('High', 'Reflective XSS', desc))
            
        # Check 3: SQL Syntax Error Leakage
        sql_payload = "'"
        sql_url = f"{url}?id={sql_payload}&cat={sql_payload}"
        sql_response = requests.get(sql_url, timeout=10)
        
        sql_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark after the character string", "quoted string not properly terminated"]
        if any(err in sql_response.text.lower() for err in sql_errors):
            desc = "Possible SQL Injection. Database syntax error leaked in the HTTP response."
            add_vulnerability(asset_id, 'Critical', 'SQL Injection (Error-Based)', desc)
            findings.append(('Critical', 'SQL Injection (Error-Based)', desc))
            
        return True, findings
        
    except requests.exceptions.RequestException as e:
        return False, f"Network error during scan: {str(e)}"
    except Exception as e:
        return False, str(e)
