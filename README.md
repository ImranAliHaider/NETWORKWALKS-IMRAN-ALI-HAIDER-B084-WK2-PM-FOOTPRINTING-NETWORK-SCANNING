# Networkwalks Cybersecurity Internship — Week 02

**Footprinting, Reconnaissance & Network Scanning**

---

## Overview

This repository documents my practical work, technical commands, findings, and risk assessments completed during **Week 02** of the **Networkwalks Cybersecurity Internship Program** (Batch: `B084-Networkwalks`).

The week's tasks covered the first two phases of a structured penetration test:
1. **Phase 1 — Reconnaissance & Footprinting (`W2-PM1`):** Passive and light active intelligence gathering against `networkwalks.com` using six Kali Linux reconnaissance utilities.
2. **Phase 2 — Scanning & Network Discovery (`W2-PM5`):** Host discovery, port enumeration, service/version detection, OS fingerprinting, and topology visualization against my local Kali Linux virtual machine (`127.0.0.1`) using `Nmap` and `Zenmap`.

All activities were executed strictly for educational and research purposes within an authorized scope—governed by a written **Letter of Authorization** from Networkwalks and restricted to my personally owned lab environment.

---

## Learning Objectives

* Understand passive and active footprinting methodologies and how reconnaissance transitions into network scanning.
* Query domain registration records, registrar details, domain lock statuses, and DNSSEC configurations.
* Enumerate authoritative DNS records (`A`, `NS`, `MX`, `TXT`, `SOA`, `SRV`) and identify underlying DNS server software.
* Fingerprint target web stacks, CMS/plugin versions, exposed REST APIs, cookie attributes, and HTTP security headers.
* Detect the presence and vendor of Web Application Firewalls (WAF).
* Execute ping sweeps, TCP service/version scans, aggressive OS detection scans, and graphical topology mapping with `Nmap` and `Zenmap`.
* Evaluate reconnaissance observations by risk severity and formulate actionable hardening recommendations.

---

## Practical Modules & Tools Used

| Module | Topic | Tools / Utilities | Target Scope |
| :--- | :--- | :--- | :--- |
| **W2-PM1** | Footprinting with Multiple Kali Tools | `whois`, `nslookup`, `whatweb`, `curl`, `wafw00f`, `dnsrecon` | `networkwalks.com` (Authorized via LoA) |
| **W2-PM5** | Network Scanning & Discovery | `nmap`, `zenmap` (Nmap GUI) | `127.0.0.1` / `localhost` (Own Kali Linux VM) |

**Environment & Documentation Stack:**
* **Operating System:** Kali Linux (VirtualBox VM)
* **Local Test Service:** Apache2 HTTP Server (Debian)
* **Reporting & Evidence:** Penetration Testing PDF Report with 17 annotated terminal & GUI screenshots

---

## Detailed Activities & Technical Findings

### Part 1: Footprinting & Reconnaissance (`W2-PM1` — `networkwalks.com`)

I executed six distinct reconnaissance tools from Kali Linux to map the public footprint of `networkwalks.com` without performing any intrusive exploitation or brute-forcing:

#### 1. Domain Registration Lookup (`whois`)
* **Command Executed:** `whois networkwalks.com`
* **Key Findings:**
  * **Registrar:** GoDaddy.com, LLC (`whois.godaddy.com`).
  * **Domain Timeline:** Created on `6 November 2019`, last updated on `12 November 2025`, and set to expire on `6 November 2027`.
  * **Name Servers:** `NS6135.HOSTGATOR.COM` and `NS6136.HOSTGATOR.COM` (DNS hosted on HostGator).
  * **Security Controls:** All four ICANN client lock statuses (`clientDeleteProhibited`, `clientRenewProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`) are active, while `DNSSEC` is `unsigned`.

#### 2. DNS Record Resolution (`nslookup`)
* **Commands Executed:**
  * `nslookup networkwalks.com`
  * `nslookup -type=NS networkwalks.com`
  * `nslookup -type=MX networkwalks.com`
  * `nslookup -type=TXT networkwalks.com`
* **Key Findings:**
  * **A Record:** Resolves to `192.232.216.135` (queried via Google resolver `8.8.8.8`).
  * **NS Records:** `ns6135.hostgator.com` and `ns6136.hostgator.com`.
  * **MX Record:** Handled by `mail.networkwalks.com` (priority `0`).
  * **TXT Records:** Exposed a Google Site Verification token (`google-site-verification=...`) and an SPF record configured with a soft-fail policy (`v=spf1 +a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all`).

#### 3. Web Technology Fingerprinting (`whatweb`)
* **Command Executed:** `whatweb networkwalks.com`
* **Key Findings:**
  * **Redirection & Server:** HTTP (`http://networkwalks.com`) performs a `301 Moved Permanently` redirect to HTTPS (`https://networkwalks.com/`) running on **Apache**.
  * **CMS & Plugins:** Identified **WordPress `7.1.4`** and **WordPress Download Manager `3.3.76`** via meta generator tags, alongside **jQuery `3.7.1`** and **Google Tag Manager**. *(Filtered out a false-positive Bootstrap `7.1.4` version match caused by WordPress version mirroring).*
  * **Contact & Session Details:** Discovered public email `info@networkwalks.com` and observed the `_wpdm_client` session cookie configured with the `HttpOnly` flag.

#### 4. HTTP Response Header Inspection (`curl`)
* **Command Executed:** `curl -I https://networkwalks.com`
* **Key Findings:**
  * **Protocol & Server Banner:** Responded with `HTTP/2 200` and generic `server: Apache` (version banner hidden).
  * **Present Headers & Flags:** `Permissions-Policy`, `Referrer-Policy` (`no-referrer-when-downgrade`), caching headers (`x-nginx-cache`, `x-endurance-cache-level`), `Secure` + `HttpOnly` cookie flags, and a `Link` header advertising the WordPress REST API endpoint (`/wp-json/`).
  * **Missing Security Headers:** `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, and `X-Content-Type-Options` were absent in the response.

#### 5. Web Application Firewall Detection (`wafw00f`)
* **Command Executed:** `wafw00f https://networkwalks.com`
* **Key Findings:**
  * Confirmed in 2 HTTP requests that `networkwalks.com` is protected behind a **ModSecurity (SpiderLabs)** Web Application Firewall.

#### 6. Standard DNS Enumeration (`dnsrecon`)
* **Command Executed:** `dnsrecon -d networkwalks.com -t std`
* **Key Findings:**
  * Enumerated 8 DNS records across `SOA`, `NS`, `MX`, `A`, `TXT`, and `SRV` types.
  * Confirmed web and mail services share `192.232.216.135`, while name servers reside at `50.87.144.87` (`ns6135`) and `192.232.216.131` (`ns6136`).
  * **Software Version Disclosure:** Both authoritative name servers disclosed their DNS daemon version as **BIND `9.16.23-RH`**.
  * **SRV Records:** Discovered 8 `_autodiscover._tcp` records pointing to `cpanelemaildiscovery.cpanel.net`.

---

### Part 2: Network Scanning & Discovery (`W2-PM5` — `127.0.0.1`)

To practice active network discovery safely within scope, I temporarily started a local **Apache2** web server on my Kali Linux VM (`127.0.0.1`), executed terminal and GUI scans, and stopped the service afterward:

#### 1. Host Discovery (Ping Scan)
* **Commands Executed:** `nmap -sn 127.0.0.1` (Terminal) & Zenmap *Ping scan* profile
* **Findings:** Confirmed the loopback target (`localhost` / `127.0.0.1`) was active (`1 IP address scanned, 1 host up`).

#### 2. Port & Service Version Detection
* **Command Executed:** `sudo nmap -sV 127.0.0.1`
* **Findings:** Scanned 1,000 TCP ports in `6.27 seconds`; found 999 closed ports and **1 open port**: `80/tcp open http — Apache httpd 2.4.69 ((Debian))`.

#### 3. Aggressive Scan & OS Fingerprinting
* **Command Executed:** `sudo nmap -A 127.0.0.1`
* **Findings:** Extracted the HTTP page title (`Apache2 Debian Default Page: It works`), full server header (`Apache/2.4.69 (Debian)`), network distance (`0 hops`), and an OS fingerprint guess of **Linux `5.0 – 6.2` (97% confidence)**.

#### 4. Zenmap Graphical Intense Scan & Topology Analysis
* **Command Executed:** `nmap -T4 -A -v 127.0.0.1` (Zenmap *Intense scan* profile)
* **Findings:** Completed in `18.75 seconds`. Analyzed results across four Zenmap views:
  * **Ports/Hosts Tab:** Verified `80/tcp` running `Apache httpd 2.4.69`.
  * **Host Details Tab:** Reviewed open/closed port counts (`1` open / `999` closed), IPv4 (`127.0.0.1`), PTR hostname (`localhost`), and OS details.
  * **Topology Tab:** Visualized the single-node local host graph (`localhost`).

---

## Risk Analysis & Security Recommendations

Based on the reconnaissance and scanning data, I categorized **7 informational/security observations** (rated **Medium** or **Low** since no exploitation was performed):

| # | Observation | Technical Evidence | Risk Level | Key Recommendation |
| :--- | :--- | :--- | :---: | :--- |
| **1** | CMS & Plugin Versions Exposed | WordPress `7.1.4` & Download Manager `3.3.76` visible in meta tags | **Medium** | Strip WordPress generator meta tags and keep core/plugins updated. |
| **2** | Missing Browser Security Headers | Absence of HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`; `/wp-json/` exposed | **Medium** | Enforce HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, and `SameSite` cookie attributes. |
| **3** | DNS & Mail Configuration Exposed | BIND `9.16.23-RH` banner disclosed; SPF uses soft-fail (`~all`) | **Medium** | Mask BIND version strings, tighten SPF to hard-fail (`-all`), and configure DKIM/DMARC. |
| **4** | Shared Hosting Infrastructure Identifiable | Web, mail, and NS hosted on HostGator (`192.232.216.135`) | **Low** | Monitor shared hosting attack surface and segment critical services where possible. |
| **5** | WAF Technology Identifiable | ModSecurity (SpiderLabs) detected via `wafw00f` | **Low** | Keep ModSecurity rulesets updated and actively monitor WAF logs. |
| **6** | DNSSEC Not Enabled | `DNSSEC: unsigned` in `whois` and no DNSSEC records in `dnsrecon` | **Low** | Enable DNSSEC signing through the registrar/DNS provider. |
| **7** | Local Service Banner & Default Page | Port `80/tcp` exposed `Apache/2.4.69 (Debian)` default page on `127.0.0.1` | **Low** | Disable unneeded services, remove default pages, and set `ServerTokens Prod` & `ServerSignature Off`. |

---

## Final Project Report

The complete Week 02 Penetration Testing Report is included in this repository inside the `report/` directory.

* **Report Path:** `report/Week-02-Penetration-Testing-Report.pdf`
* **Contents:** Liability Disclaimer, Scope & Authorization, Tool Matrix, Step-by-Step Command Outputs, Risk Assessment Table, 9 Security Hardening Recommendations, Conclusion, and **17 full-resolution screenshots** (`Screenshot 1` through `Screenshot 17`).

---

## Scope & Ethical Compliance

* **Authorized Targets Only:** Testing was strictly bounded by a written **Letter of Authorization** for `networkwalks.com` and personal ownership of the Kali Linux virtual machine (`127.0.0.1`).
* **Non-Intrusive Methodology:** Only passive OSINT/DNS queries and basic local port scans were performed; no vulnerability exploitation, password attacks, or denial-of-service tests were conducted.
* **Responsible Handling:** All discovered data was treated strictly as reconnaissance observations for educational reporting.

---
## Program Information

**Program:** Cybersecurity Program — Networkwalks  
**Week:** 02  
**Focus:** Footprinting, Reconnaissance & Network Scanning  
**Author:** Imran Ali Haider


---

*Learning by practicing. Building cybersecurity skills through hands-on labs and responsible security research.*