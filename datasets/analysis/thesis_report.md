# Master's Thesis: Web Security & Misconfiguration Detection System

## Executive Summary
This project presents a comprehensive toolset for identifying security vulnerabilities in web applications and misconfigurations in Apache HTTP Server setups. The system combines static analysis of configuration files with dynamic vulnerability scanning of live web targets.

## Component 1: Apache Misconfiguration Detector
The detector performs deep static analysis on `httpd.conf` and `.htaccess` files using 14 specialized security rules:
- **CA8**: ProxyPass inside Directory blocks.
- **SSL Hardening**: Detection of weak protocols (SSLv3, TLS 1.0) and weak ciphers.
- **Information Disclosure**: ServerSignature and ServerTokens exposure.
- **Hardening Rules**: Directory listing (Indexes), TRACE method, and missing security headers.

## Component 2: Web Vulnerability Scanner
A multi-threaded dynamic scanner capable of identifying 20+ vulnerability types:
- **Active Tests**: SQL Injection, Reflected XSS, IDOR, XXE Susceptibility.
- **Passive Tests**: Missing CSP/HSTS headers, Insecure Cookie flags, Server Banner disclosures.
- **Access Control**: Dangerous HTTP methods, Permissive CORS policies, CSRF token absence.

## Methodology
The system utilizes a Python/Requests-based scanning engine with robust retry logic and multiple protocol attempts (HTTP/HTTPS/WWW). Results are classified by severity (CRITICAL to LOW) and mapped to CWE and OWASP Top 10 categories.

## Performance & Reliability
- **Retry Logic**: Ensures connectivity to diverse web targets.
- **Professional Reporting**: Generates both academic Markdown reports and data-driven CSV summaries.
- **User Interface**: A modern, dark-themed Flask web application for seamless interaction and real-time scanning feedback.

## Conclusion
The system successfully bridges the gap between server-side configuration security and client-side application vulnerability assessment, providing a robust, thesis-grade tool for cybersecurity professionals and researchers.
