# Networkwalks Cybersecurity Internship — Week 02

**Footprinting, Reconnaissance & Network Scanning**

---

## Overview

This repository documents my practical work, technical commands, findings, and risk assessments completed during **Week 02** of the **Networkwalks Cybersecurity Internship Program** (Batch: `B084-Networkwalks`)[span_0](start_span)[span_0](end_span)[span_1](start_span)[span_1](end_span).

The week's tasks covered the first two phases of a structured penetration test[span_2](start_span)[span_2](end_span):
1. **Phase 1 — Reconnaissance & Footprinting (`W2-PM1`):** Passive and light active intelligence gathering against `networkwalks.com` using six Kali Linux reconnaissance utilities[span_3](start_span)[span_3](end_span)[span_4](start_span)[span_4](end_span).
2. **Phase 2 — Scanning & Network Discovery (`W2-PM5`):** Host discovery, port enumeration, service/version detection, OS fingerprinting, and topology visualization against my local Kali Linux virtual machine (`127.0.0.1`) using `Nmap` and `Zenmap`[span_5](start_span)[span_5](end_span)[span_6](start_span)[span_6](end_span)[span_7](start_span)[span_7](end_span).

All activities were executed strictly for educational and research purposes within an authorized scope—governed by a written **Letter of Authorization** from Networkwalks and restricted to my personally owned lab environment[span_8](start_span)[span_8](end_span).

---

## Learning Objectives

* Understand passive and active footprinting methodologies and how reconnaissance transitions into network scanning[span_9](start_span)[span_9](end_span)[span_10](start_span)[span_10](end_span).
* Query domain registration records, registrar details, domain lock statuses, and DNSSEC configurations[span_11](start_span)[span_11](end_span).
* Enumerate authoritative DNS records (`A`, `NS`, `MX`, `TXT`, `SOA`, `SRV`) and identify underlying DNS server software[span_12](start_span)[span_12](end_span).
* Fingerprint target web stacks, CMS/plugin versions, exposed REST APIs, cookie attributes, and HTTP security headers[span_13](start_span)[span_13](end_span).
* Detect the presence and vendor of Web Application Firewalls (WAF)[span_14](start_span)[span_14](end_span).
* Execute ping sweeps, TCP service/version scans, aggressive OS detection scans, and graphical topology mapping with `Nmap` and `Zenmap`[span_15](start_span)[span_15](end_span).
* Evaluate reconnaissance observations by risk severity and formulate actionable hardening recommendations[span_16](start_span)[span_16](end_span)[span_17](start_span)[span_17](end_span).

---

## Practical Modules & Tools Used

| Module | Topic | Tools / Utilities | Target Scope |
| :--- | :--- | :--- | :--- |
| **W2-PM1** | Footprinting with Multiple Kali Tools[span_18](start_span)[span_18](end_span) | `whois`, `nslookup`, `whatweb`, `curl`, `wafw00f`, `dnsrecon`[span_19](start_span)[span_19](end_span)[span_20](start_span)[span_20](end_span) | `networkwalks.com` (Authorized via LoA)[span_21](start_span)[span_21](end_span) |
| **W2-PM5** | Network Scanning & Discovery[span_22](start_span)[span_22](end_span) | `nmap`, `zenmap` (Nmap GUI)[span_23](start_span)[span_23](end_span) | `127.0.0.1` / `localhost` (Own Kali Linux VM)[span_24](start_span)[span_24](end_span)[span_25](start_span)[span_25](end_span) |

**Environment & Documentation Stack:**
* **Operating System:** Kali Linux (VirtualBox VM)[span_26](start_span)[span_26](end_span)
* **Local Test Service:** Apache2 HTTP Server (Debian)[span_27](start_span)[span_27](end_span)
* **Reporting & Evidence:** Penetration Testing PDF Report with 17 annotated terminal & GUI screenshots[span_28](start_span)[span_28](end_span)[span_29](start_span)[span_29](end_span)[span_30](start_span)[span_30](end_span)[span_31](start_span)[span_31](end_span)[span_32](start_span)[span_32](end_span)[span_33](start_span)[span_33](end_span)[span_34](start_span)[span_34](end_span)[span_35](start_span)[span_35](end_span)[span_36](start_span)[span_36](end_span)

---

## Detailed Activities & Technical Findings

### Part 1: Footprinting & Reconnaissance (`W2-PM1` — `networkwalks.com`)

I executed six distinct reconnaissance tools from Kali Linux to map the public footprint of `networkwalks.com` without performing any intrusive exploitation or brute-forcing[span_37](start_span)[span_37](end_span):

#### 1. Domain Registration Lookup (`whois`)
* **Command Executed:** `whois networkwalks.com`[span_38](start_span)[span_38](end_span)
* **Key Findings:**
  * **Registrar:** GoDaddy.com, LLC (`whois.godaddy.com`)[span_39](start_span)[span_39](end_span)[span_40](start_span)[span_40](end_span).
  * **Domain Timeline:** Created on `6 November 2019`, last updated on `12 November 2025`, and set to expire on `6 November 2027`[span_41](start_span)[span_41](end_span)[span_42](start_span)[span_42](end_span).
  * **Name Servers:** `NS6135.HOSTGATOR.COM` and `NS6136.HOSTGATOR.COM` (DNS hosted on HostGator)[span_43](start_span)[span_43](end_span)[span_44](start_span)[span_44](end_span).
  * **Security Controls:** All four ICANN client lock statuses (`clientDeleteProhibited`, `clientRenewProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`) are active, while `DNSSEC` is `unsigned`[span_45](start_span)[span_45](end_span)[span_46](start_span)[span_46](end_span).

#### 2. DNS Record Resolution (`nslookup`)
* **Commands Executed:**[span_47](start_span)[span_47](end_span)
  * `nslookup networkwalks.com`[span_48](start_span)[span_48](end_span)
  * `nslookup -type=NS networkwalks.com`[span_49](start_span)[span_49](end_span)[span_50](start_span)[span_50](end_span)
  * `nslookup -type=MX networkwalks.com`[span_51](start_span)[span_51](end_span)[span_52](start_span)[span_52](end_span)
  * `nslookup -type=TXT networkwalks.com`[span_53](start_span)[span_53](end_span)[span_54](start_span)[span_54](end_span)
* **Key Findings:**
  * **A Record:** Resolves to `192.232.216.135` (queried via Google resolver `8.8.8.8`)[span_55](start_span)[span_55](end_span)[span_56](start_span)[span_56](end_span).
  * **NS Records:** `ns6135.hostgator.com` and `ns6136.hostgator.com`[span_57](start_span)[span_57](end_span)[span_58](start_span)[span_58](end_span).
  * **MX Record:** Handled by `mail.networkwalks.com` (priority `0`)[span_59](start_span)[span_59](end_span).
  * **TXT Records:** Exposed a Google Site Verification token (`google-site-verification=...`) and an SPF record configured with a soft-fail policy (`v=spf1 +a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all`)[span_60](start_span)[span_60](end_span)[span_61](start_span)[span_61](end_span).

#### 3. Web Technology Fingerprinting (`whatweb`)
* **Command Executed:** `whatweb networkwalks.com`[span_62](start_span)[span_62](end_span)
* **Key Findings:**
  * **Redirection & Server:** HTTP (`http://networkwalks.com`) performs a `301 Moved Permanently` redirect to HTTPS (`https://networkwalks.com/`) running on **Apache**[span_63](start_span)[span_63](end_span)[span_64](start_span)[span_64](end_span).
  * **CMS & Plugins:** Identified **WordPress `7.1.4`** and **WordPress Download Manager `3.3.76`** via meta generator tags, alongside **jQuery `3.7.1`** and **Google Tag Manager**[span_65](start_span)[span_65](end_span)[span_66](start_span)[span_66](end_span). *(Filtered out a false-positive Bootstrap `7.1.4` version match caused by WordPress version mirroring).*[span_67](start_span)[span_67](end_span)
  * **Contact & Session Details:** Discovered public email `info@networkwalks.com` and observed the `_wpdm_client` session cookie configured with the `HttpOnly` flag[span_68](start_span)[span_68](end_span)[span_69](start_span)[span_69](end_span).

#### 4. HTTP Response Header Inspection (`curl`)
* **Command Executed:** `curl -I https://networkwalks.com`[span_70](start_span)[span_70](end_span)[span_71](start_span)[span_71](end_span)
* **Key Findings:**
  * **Protocol & Server Banner:** Responded with `HTTP/2 200` and generic `server: Apache` (version banner hidden)[span_72](start_span)[span_72](end_span)[span_73](start_span)[span_73](end_span).
  * **Present Headers & Flags:** `Permissions-Policy`, `Referrer-Policy` (`no-referrer-when-downgrade`), caching headers (`x-nginx-cache`, `x-endurance-cache-level`), `Secure` + `HttpOnly` cookie flags, and a `Link` header advertising the WordPress REST API endpoint (`/wp-json/`)[span_74](start_span)[span_74](end_span)[span_75](start_span)[span_75](end_span).
  * **Missing Security Headers:** `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, and `X-Content-Type-Options` were absent in the response[span_76](start_span)[span_76](end_span).

#### 5. Web Application Firewall Detection (`wafw00f`)
* **Command Executed:** `wafw00f https://networkwalks.com`[span_77](start_span)[span_77](end_span)[span_78](start_span)[span_78](end_span)
* **Key Findings:**
  * Confirmed in 2 HTTP requests that `networkwalks.com` is protected behind a **ModSecurity (SpiderLabs)** Web Application Firewall[span_79](start_span)[span_79](end_span)[span_80](start_span)[span_80](end_span).

#### 6. Standard DNS Enumeration (`dnsrecon`)
* **Command Executed:** `dnsrecon -d networkwalks.com -t std`[span_81](start_span)[span_81](end_span)[span_82](start_span)[span_82](end_span)
* **Key Findings:**
  * Enumerated 8 DNS records across `SOA`, `NS`, `MX`, `A`, `TXT`, and `SRV` types[span_83](start_span)[span_83](end_span).
  * Confirmed web and mail services share `192.232.216.135`, while name servers reside at `50.87.144.87` (`ns6135`) and `192.232.216.131` (`ns6136`)[span_84](start_span)[span_84](end_span)[span_85](start_span)[span_85](end_span).
  * **Software Version Disclosure:** Both authoritative name servers disclosed their DNS daemon version as **BIND `9.16.23-RH`**[span_86](start_span)[span_86](end_span)[span_87](start_span)[span_87](end_span).
  * **SRV Records:** Discovered 8 `_autodiscover._tcp` records pointing to `cpanelemaildiscovery.cpanel.net`[span_88](start_span)[span_88](end_span)[span_89](start_span)[span_89](end_span).

---

### Part 2: Network Scanning & Discovery (`W2-PM5` — `127.0.0.1`)

To practice active network discovery safely within scope, I temporarily started a local **Apache2** web server on my Kali Linux VM (`127.0.0.1`), executed terminal and GUI scans, and stopped the service afterward[span_90](start_span)[span_90](end_span)[span_91](start_span)[span_91](end_span)[span_92](start_span)[span_92](end_span):

#### 1. Host Discovery (Ping Scan)
* **Commands Executed:** `nmap -sn 127.0.0.1` (Terminal) & Zenmap *Ping scan* profile[span_93](start_span)[span_93](end_span)[span_94](start_span)[span_94](end_span)
* **Findings:** Confirmed the loopback target (`localhost` / `127.0.0.1`) was active (`1 IP address scanned, 1 host up`)[span_95](start_span)[span_95](end_span)[span_96](start_span)[span_96](end_span).

#### 2. Port & Service Version Detection
* **Command Executed:** `sudo nmap -sV 127.0.0.1`[span_97](start_span)[span_97](end_span)[span_98](start_span)[span_98](end_span)
* **Findings:** Scanned 1,000 TCP ports in `6.27 seconds`; found 999 closed ports and **1 open port**: `80/tcp open http — Apache httpd 2.4.69 ((Debian))`[span_99](start_span)[span_99](end_span)[span_100](start_span)[span_100](end_span).

#### 3. Aggressive Scan & OS Fingerprinting
* **Command Executed:** `sudo nmap -A 127.0.0.1`[span_101](start_span)[span_101](end_span)[span_102](start_span)[span_102](end_span)
* **Findings:** Extracted the HTTP page title (`Apache2 Debian Default Page: It works`), full server header (`Apache/2.4.69 (Debian)`), network distance (`0 hops`), and an OS fingerprint guess of **Linux `5.0 – 6.2` (97% confidence)**[span_103](start_span)[span_103](end_span)[span_104](start_span)[span_104](end_span).

#### 4. Zenmap Graphical Intense Scan & Topology Analysis
* **Command Executed:** `nmap -T4 -A -v 127.0.0.1` (Zenmap *Intense scan* profile)[span_105](start_span)[span_105](end_span)[span_106](start_span)[span_106](end_span)
* **Findings:** Completed in `18.75 seconds`[span_107](start_span)[span_107](end_span)[span_108](start_span)[span_108](end_span). Analyzed results across four Zenmap views[span_109](start_span)[span_109](end_span)[span_110](start_span)[span_110](end_span)[span_111](start_span)[span_111](end_span)[span_112](start_span)[span_112](end_span):
  * **Ports/Hosts Tab:** Verified `80/tcp` running `Apache httpd 2.4.69`[span_113](start_span)[span_113](end_span)[span_114](start_span)[span_114](end_span).
  * **Host Details Tab:** Reviewed open/closed port counts (`1` open / `999` closed), IPv4 (`127.0.0.1`), PTR hostname (`localhost`), and OS details[span_115](start_span)[span_115](end_span)[span_116](start_span)[span_116](end_span).
  * **Topology Tab:** Visualized the single-node local host graph (`localhost`)[span_117](start_span)[span_117](end_span)[span_118](start_span)[span_118](end_span).

---

## Risk Analysis & Security Recommendations

Based on the reconnaissance and scanning data, I categorized **7 informational/security observations** (rated **Medium** or **Low** since no exploitation was performed)[span_119](start_span)[span_119](end_span)[span_120](start_span)[span_120](end_span):

| # | Observation | Technical Evidence | Risk Level | Key Recommendation |
| :--- | :--- | :--- | :---: | :--- |
| **1** | CMS & Plugin Versions Exposed[span_121](start_span)[span_121](end_span) | WordPress `7.1.4` & Download Manager `3.3.76` visible in meta tags[span_122](start_span)[span_122](end_span) | **Medium**[span_123](start_span)[span_123](end_span) | Strip WordPress generator meta tags and keep core/plugins updated[span_124](start_span)[span_124](end_span). |
| **2** | Missing Browser Security Headers[span_125](start_span)[span_125](end_span) | Absence of HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`; `/wp-json/` exposed[span_126](start_span)[span_126](end_span) | **Medium**[span_127](start_span)[span_127](end_span) | Enforce HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, and `SameSite` cookie attributes[span_128](start_span)[span_128](end_span). |
| **3** | DNS & Mail Configuration Exposed[span_129](start_span)[span_129](end_span) | BIND `9.16.23-RH` banner disclosed; SPF uses soft-fail (`~all`)[span_130](start_span)[span_130](end_span) | **Medium**[span_131](start_span)[span_131](end_span) | Mask BIND version strings, tighten SPF to hard-fail (`-all`), and configure DKIM/DMARC[span_132](start_span)[span_132](end_span). |
| **4** | Shared Hosting Infrastructure Identifiable[span_133](start_span)[span_133](end_span) | Web, mail, and NS hosted on HostGator (`192.232.216.135`)[span_134](start_span)[span_134](end_span) | **Low**[span_135](start_span)[span_135](end_span) | Monitor shared hosting attack surface and segment critical services where possible. |
| **5** | WAF Technology Identifiable[span_136](start_span)[span_136](end_span) | ModSecurity (SpiderLabs) detected via `wafw00f`[span_137](start_span)[span_137](end_span) | **Low**[span_138](start_span)[span_138](end_span) | Keep ModSecurity rulesets updated and actively monitor WAF logs[span_139](start_span)[span_139](end_span). |
| **6** | DNSSEC Not Enabled[span_140](start_span)[span_140](end_span) | `DNSSEC: unsigned` in `whois` and no DNSSEC records in `dnsrecon`[span_141](start_span)[span_141](end_span) | **Low**[span_142](start_span)[span_142](end_span) | Enable DNSSEC signing through the registrar/DNS provider[span_143](start_span)[span_143](end_span). |
| **7** | Local Service Banner & Default Page[span_144](start_span)[span_144](end_span) | Port `80/tcp` exposed `Apache/2.4.69 (Debian)` default page on `127.0.0.1`[span_145](start_span)[span_145](end_span) | **Low**[span_146](start_span)[span_146](end_span) | Disable unneeded services, remove default pages, and set `ServerTokens Prod` & `ServerSignature Off`[span_147](start_span)[span_147](end_span). |

---

## Final Project Report

The complete Week 02 Penetration Testing Report is included in this repository inside the `report/` directory[span_148](start_span)[span_148](end_span).

* **Report Path:** `report/Week-02-Penetration-Testing-Report.pdf` (currently uploaded as `Wow.pdf`)[span_149](start_span)[span_149](end_span)
* **Contents:** Liability Disclaimer, Scope & Authorization, Tool Matrix, Step-by-Step Command Outputs, Risk Assessment Table, 9 Security Hardening Recommendations, Conclusion, and **17 full-resolution screenshots** (`Screenshot 1` through `Screenshot 17`)[span_150](start_span)[span_150](end_span)[span_151](start_span)[span_151](end_span)[span_152](start_span)[span_152](end_span)[span_153](start_span)[span_153](end_span)[span_154](start_span)[span_154](end_span)[span_155](start_span)[span_155](end_span)[span_156](start_span)[span_156](end_span)[span_157](start_span)[span_157](end_span)[span_158](start_span)[span_158](end_span)[span_159](start_span)[span_159](end_span)[span_160](start_span)[span_160](end_span).

---

## Scope & Ethical Compliance

* **Authorized Targets Only:** Testing was strictly bounded by a written **Letter of Authorization** for `networkwalks.com` and personal ownership of the Kali Linux virtual machine (`127.0.0.1`)[span_161](start_span)[span_161](end_span).
* **Non-Intrusive Methodology:** Only passive OSINT/DNS queries and basic local port scans were performed; no vulnerability exploitation, password attacks, or denial-of-service tests were conducted[span_162](start_span)[span_162](end_span)[span_163](start_span)[span_163](end_span).
* **Responsible Handling:** All discovered data was treated strictly as reconnaissance observations for educational reporting[span_164](start_span)[span_164](end_span).

---

## Program Information
Program: Cybersecurity Program — Networkwalks
Week: 02
Focus: Footprinting, Reconnaissance & Network Scanning
Author: Imran Ali Haider
GitHub: 


