# Rekall-Penetration-Test
# Introduction
This repository contains the penetration test report for Rekall Corporation, documenting the security assessment conducted on its internal network and web applications. The objective of this assessment was to identify, exploit, and analyze vulnerabilities within the environment while providing recommendations for remediation.

Testing was conducted between February 3rd through February 7th, 2025, focusing on:
* Black-box testing of Rekall’s web application and internal network, identifying and exploiting vulnerabilities without prior knowledge or administrator access.
* Enumeration and exploitation of accessible sensitive data within Rekall’s databases to assess potential impact and risk exposure.
* Comprehensive documentation of attack paths, methodologies, and remediation strategies.
# Objectives
The primary goals of the penetration test were to:

1. Identify and exfiltrate sensitive information within the domain.

2. Escalate privileges to gain higher-level access.

3. Compromise as many systems as possible.

# Methodology
**Reconnaissance**
-Conducted Open Source Intelligence (OSINT) gathering to enumerate publicly available data related to Rekall Corporation.
-Performed active reconnaissance using tools like Nmap, BloodHound, and OSINT frameworks to map out potential attack vectors.

**Vulnerability Identification & Exploitation**
-Identified vulnerable services using automated and manual enumeration techniques with tools such as Metasploit, Burp Suite, and Hashcat.
-Exploited identified weaknesses to gain unauthorized access, escalate privileges, and maintain persistence.

**Reporting**
-Documented all findings, including vulnerability details, exploitation methods, and remediation recommendations.
-Ensured proper cleanup of tools and files from the testing environment after completion.
# Scope
The penetration test scope, as defined by Rekall Corporation, included:

**Web Application** – Testing for OWASP Top 10 vulnerabilities and web-based attack vectors.

**Internal Network** – Assessment of:
  * Linux Servers
  * Windows Workstations
  * Active Directory Domain Controller
# Executive Summary
The penetration test was conducted in **three phases**:

1. Web Application Testing – Identified multiple security flaws, including Cross-Site Scripting (XSS), SQL Injection, and session hijacking vulnerabilities. Lack of Multi-Factor Authentication (MFA) and poor access control mechanisms contributed to an increased attack surface.

2. Linux Penetration Testing – Discovered critical Remote Code Execution (RCE) vulnerabilities, weak password policies, and unpatched software. Exploited Apache Tomcat CVE-2017-12617 and Shellshock CVE-2014-6271 to gain system-level access.

3. Windows Penetration Testing – Conducted Active Directory enumeration and exploited misconfigurations to obtain Domain Admin privileges. Used credential dumping techniques (SAM, LSASS, DCSync attacks) to gain persistent access to sensitive data.

These vulnerabilities pose an immediate risk to Rekall’s security posture. The report provides detailed remediation recommendations, including patch management, network segmentation, and enforcement of security best practices.

# Key Findings
FORMAT: (Vulnerability | Severity)

* XSS payload | Critical
* XSS payload PT 3 | Critical
* LFI exploit | Critical
* SQL injection | Critical
* Admin credentials left in HTML | Critical
* Network Host Enumeration via Nmap | Critical
* Drupal CMS Detection via Aggressive Scanning | Critical
* Remote Code Executinon Vulnerability Detected | Critical
* Root Access via Stolen SSH Credentials | Critical
* Shellshock Eploitation in Apache | Critical
* Credentials Exposed in Public GitHub Repository | Critical
* SLMail Exploit Remote Code Execution | Critical
* Unauthorized Access via Meterpreter Session | Critical
* Privilege Escalation via SLMail Exploit & NTLM Hash Dumping | Critical
* Cached Credential Dumping & Lateral Movement to Server2019 | Critical
* XSS payload PT 2 | High
* Sensitive Files Accessible via URL Manipulation | High
* Unrestricted access to to sensitive pages | High
* Drupal CMS Detection via Aggressive Scanning | High
* Open HTTP Port with exposed Credentials | High
* Anonymous FTP Access Exposes Sensitive Files | High
* Scheduled task enumeration via meterpreter | High
* Unrestricted Access to Root directory | High
* Public WHOIS Data Exposure | Medium
* SSL Certificate Transparency Exposure | Low
* Publicly Discoverable IP address | Low
