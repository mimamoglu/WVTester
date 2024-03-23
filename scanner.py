#!/usr/bin/env python3

import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os
import socket as s
from urllib.parse import urlparse
from pprint import pprint


red = "\033[91m"
yellow = "\033[93m"
green = "\033[32m"
end_color = "\033[0m"
warn = "[***]"
warning = f"{red}{warn}{end_color}"
ri = "[Risk Report]"
risk = f"{yellow}{ri}{end_color}"
sugg = "[Suggestions]"
suggestion = f"{green}{sugg}{end_color}"


class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links_from(self, url):
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.text)

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urljoin(url, link)

            if "#" in link:
                link = link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, "html.parser")
        return parsed_html.find_all("form")

    def get_form_details(self, form):
        details = {}
        try:
            action = form.attrs.get("action").lower()
        except:
            action = None
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")

        input_list = form.find_all("input")
        post_data = {}
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value

        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print(warning + " XSS discovered in " + link + " in the following form:")
                    print(form)
                    print(risk + " Malicious actors can inject and execute arbitrary scripts within the context of a user's browser.")
                    print("This poses a significant security risk, as attackers can potentially steal sensitive information, hijack user sessions, or deface the website.")
                    self.xxs_vulnerability_suggestion()
                is_vulnerable_to_commandi = self.test_command_injection_in_form(form, link)
                if is_vulnerable_to_commandi:
                    print(warning + " Command Injection discovered in " + link + " in the following form:")
                    print(form)
                    print(risk + " Attackers can execute arbitrary commands on the underlying server. ")
                    print("Command injection poses a critical security risk.")
                    print("It potentially leading to unauthorized access, data breaches, and compromise of the host system.")
                    self.commandi_vulnerability_suggestion()
                self.test_sql_injection_in_link(link)
                self.test_sql_injection_in_forms(link, form)

            if "=" in link:
                print("[+] Testing " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    print(warning + " Discovered XSS in " + link)
                    print(risk + " Malicious actors can inject and execute arbitrary scripts within the context of a user's browser.")
                    print("This poses a significant security risk, as attackers can potentially steal sensitive information, hijack user sessions, or deface the website.")
                    self.xxs_vulnerability_suggestion()

    def test_xss_in_link(self, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        return xss_test_script in response.text

    def test_xss_in_form(self, form, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        return xss_test_script in response.text

    def test_command_injection_in_form(self, form, url):
        command_injection_script = " |expr 99 + 55"
        content = "154"
        response = self.submit_form(form, command_injection_script, url)
        return content in response.text

    def get_nmap(self, options, url):
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        target_ip = s.gethostbyname(host)
        command = "nmap " + options + " " + target_ip
        process = os.popen(command)
        results = str(process.read())
        print(results)

    def is_vulnerableto_sql(self, response):
        errors = {
            # MySQL
            "you have an error in your sql syntax;",
            "warning: mysql",
            "memsql does not support this type of query",
            "mysqlclient",
            # SQL Server
            "unclosed quotation mark after the character string",
            # Oracle
            "quoted string not properly terminated",
            # PostSQL
            "valid postgresql result",
            "error:syntax error at or near",
            "postgresql query failed",
            # Microsoft SQL Server
            "odbc sql server driver",
            "microsoft sql native client error",
        }
        for error in errors:
            # if you find one of these errors, return True
            if error in response.content.decode().lower():
                return True
        # no error detected
        return False

    def test_sql_injection_in_link(self, url):
        # test on URL
        for c in "\"'":
            new_url = f"{url}{c}"
            print("[!] Trying", new_url)
            res = self.session.get(new_url)
            if self.is_vulnerableto_sql(res):
                print(warning + " SQL Injection vulnerability detected, link:", new_url)
                print(risk + " Attackers can manipulate or inject malicious SQL queries.")
                print("Potentially leading to unauthorized access, data exposure, and other severe consequences.")
                print("This is a a significant security risk.")
                self.sqli_vulnerability_suggestion()
                return

    def test_sql_injection_in_forms(self, url, form):
        # test on HTML forms
        #forms = self.extract_forms(url)
        #for form in forms:
        form_details = self.get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = self.session.post(url, data=data)
            elif form_details["method"] == "get":
                res = self.session.get(url, params=data)
            if self.is_vulnerableto_sql(res):
                print(warning + " SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                print(risk + " Attackers can manipulate or inject malicious SQL queries.")
                print("Potentially leading to unauthorized access, data exposure, and other severe consequences.")
                print("This is a a significant security risk.")
                self.sqli_vulnerability_suggestion()
                break

    def get_csrf_token(self, url):
        response = self.session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for a CSRF token in the HTML source
        csrf_token = soup.find('input', {'name': 'user_token'})

        if csrf_token:
            return csrf_token['value']
        else:
            # If not found, check for potential dynamic generation through JavaScript
            js_token = self.extract_csrf_token_from_js(url)
            if js_token:
                return js_token
            else:
                print("CSRF token not found on the page.")
                return None

    def xxs_vulnerability_suggestion(self):
        print(suggestion + """\n[0] Input Validation and Output Encoding:
Implement rigorous input validation on both client and server sides to ensure that user-supplied data is sanitized and conforms to expected patterns. Additionally, encode output data to prevent script execution.
        
[1] Content Security Policy (CSP):
Implement a Content Security Policy to restrict the sources from which the application can load scripts, mitigating the impact of XSS attacks.
        
[2] Use Secure Coding Practices:
Train developers on secure coding practices to avoid common XSS pitfalls, such as properly validating and escaping user input.
        
[3] Regular Security Audits and Penetration Testing:
Conduct regular security audits and penetration testing to identify and address potential vulnerabilities proactively.\n""")

    def commandi_vulnerability_suggestion(self):
        print(suggestion + """\n[0] Input Validation and Sanitization:
Implement strict input validation and sanitization to ensure that user input is properly validated and sanitized before being used in command execution.

[1] Parameterized Queries or Prepared Statements:
If applicable, use parameterized queries or prepared statements when interacting with databases to prevent SQL injection vulnerabilities, which may lead to command injection.

[2] Whitelisting:
Whitelist acceptable input values and reject any input that does not conform to the expected patterns. This helps prevent injection attacks by allowing only known and safe values.

[3] Least Privilege Principle:
Apply the principle of least privilege by restricting the permissions of the user account or process executing commands. Avoid executing commands with unnecessary elevated privileges.

[4] Security Audits and Code Reviews:
Conduct regular security audits and code reviews to identify and address potential vulnerabilities. Encourage secure coding practices among development teams.\n""")

    def sqli_vulnerability_suggestion(self):
        print(suggestion + """\n[0] Parameterized Queries:
Implement parameterized queries or prepared statements to ensure that user input is properly sanitized and treated as data, not executable code.

[1] Input Validation and Escaping:
Validate and sanitize user input to reject any input that does not conform to expected patterns. Additionally, use proper escaping mechanisms when embedding user input in SQL queries.

[2] Least Privilege Principle:
Apply the principle of least privilege by restricting database accounts used by the application to only the necessary permissions required for the application's functionality.

[3] Regular Security Audits and Code Reviews:
Conduct regular security audits and code reviews to identify and address potential vulnerabilities. Encourage secure coding practices among development teams.\n""")
