IoT CVE
===================================================
<p align="justify">
The following repository represents an abnormal data collection strategy for a security system in IoT. Based on a detailed risk assessment and collaboration with domain experts, the data collection framework should analyze patterns to spot potential threats and points of failure. Obtaining valid, representative, and accurate data that reflects the context and environment is critical to building an IDS fit for exploitation. 
</p>
<p align="justify">
This procedure is detailed in the article, published in Future Generation Computer Systems, entitled: 
  
> Host-based IDS: a review and open issues of an anomaly detection system in IoT
  
  https://doi.org/10.1016/j.future.2022.03.001
  
</p>

#### Real-time host-based dataset
<p align="justify">
By instancing an intrusion detection task as an anomaly detection problem, the dataset consists of expected behavior, regular system interactions, and abnormal events interpreted as threats, software errors, and vulnerabilities that can compromise the entire infrastructure. Therefore, in order to reproduce an online and incremental framework, the anomalies will be injected into the working system to evaluate its performance regarding the false alarm rates, false-negative rates, and delay between the incoming threat and its report times.
</p>
<p align="justify">
In this repository, a list of CVE, Common Vulnerabilities and Exposures, is indexed according to its attack type, identification, hardware/software required to run the exploitation, as well as a brief description. Each identification connects to another page depicting the main topics, such as the official website, the software/hardware requirements, and the instruction to execute the CVE.
</p>

---
| Attack type | CVE | Hardware / Software | Description |
|:----------------------------------------------------------------------:|:----------------------------------------------:|:-----------------------------------------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Access Control Bypass | [CVE-2019-13188](CVE-2019-13188) | Knowage<br>(FIWARE) | In Knowage through 6.1.1, an unauthenticated user can bypass access controls and access the entire application | 
| Buffer overflow / UAF | [CVE-2018-1000030](CVE-2018-1000030) | Python | Python 2.7.14 is vulnerable to a Heap-Buffer-Overflow as well as a Heap-Use-After-Free. <br> The vulnerability lies when multiply threads are handling large amounts of data. | 
| Disclosure of information about datasources including access passwords | [CVE-2019-13348](CVE-2019-13348) | Knowage<br>(FIWARE) | An authenticated user who accesses the <br> datasources page will gain access to any data <br> source credentials in cleartext, which includes databases. | 
| DoS | [CVE-2020-9283](CVE-2020-9283) | SSH (Go) | golang.org/x/crypto before <br> v0.0.0-20200220183623-bac4c82f6975<br>allows a malicious user to cause a panic <br> on an SSH server. | |
| DoS | [CVE-2020-6060](CVE-2020-6060) | MiniSNMPD | A stack buffer overflow vulnerability exists <br> in the way MiniSNMPD version 1.4 handles <br> multiple connections. A specially timed <br> sequence of SNMP connections can trigger a stack overflow, resulting in a denial of service. |
| DoS | [CVE-2019-17498](CVE-2019-17498) | Libssh2 | Libssh2 up to version 1.9.0 contains a remotely <br> triggerable out-of-bounds read, leading to denial of service or potentially to information disclosure. | 
| DoS | [CVE-2019-16279](CVE-2019-16279) | nhttpd | A memory error in the function SSL_accept allows an attacker to trigger a denial of service via a crafted HTTP request. | 
| DoS | [CVE-2019-13115](CVE-2019-13115) | Libssh2 | Libssh2 up to version 1.8.2 contains a remotely <br> triggerable out-of-bounds read, potentially leading <br> to information disclosure. | 
| DoS (Out-of-Bounds read) | [CVE-2018-7182](CVE-2018-7182) | NTP | The ctl_getitem method in ntpd in ntp-4.2.8p6 <br> before 4.2.8p11 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted mode 6 packet with a ntpd instance. | 
| Improper file access | [CVE-2018-8712](CVE-2018-8712) | Webmin | Due to weak default configuration settings, <br>limited users have full access rights to the underlying system files, allowing the user to read sensitive data from the local system. | 
| MitM | [CVE-2019-6110 / CVE-2019-6111](CVE-2019-6111) | SCP - Secure Copy <br>(openssh-clients package) | Vulnerability in OpenSSH that allows overwrite <br> in files and could possible send more responses <br> than required by user. | 
| Password Hash Disclosure | [CVE-2019-13349](CVE-2019-13349) | Knowage<br>(FIWARE) | An authenticated user that accesses the users <br> page will obtain all user password hashes. | 
| Path traversal | [CVE-2018-12015](CVE-2018-12015) | Perl | Archive::Tar module allows remote attackers to bypass a directory-traversal protection mechanism and overwrite arbitrary files. | 
| Privilege escalation | [CVE-2019-14287](CVE-2019-14287) | Sudo | An attacker with access to a Runas ALL sudoer <br> account can bypass certain policy blacklists and <br> session PAM modules, and can cause incorrect <br> logging, by invoking sudo with a crafted user ID. | 
| Privilege escalation | [CVE-2019-9891](CVE-2019-9891) | - | The function *getopt_simple* as described in *Advanced Bash Scripting Guide* allows privilege escalation and execution of commands when used in a shell script. | 
| Privilege escalation | [CVE-2019-8320](CVE-2019-8320) | Ruby | A Directory Traversal issue was discovered in RubyGems allowing to delete arbitrary files. | |
| Privilege escalation / RCE | [CVE-2019-5736](CVE-2019-5736) | Docker | The vulnerability allows a malicious container (with minimal user interaction) to overwrite the host <br><i>runc</i> binary and thus gain root-level code execution on the host. | |
| Privilege escalation | [CVE-2018-10933](CVE-2018-10933) | SSH | The **libssh**, a multiplatform library that supports <br> the SSH protocol, allows attackers to bypass authentication and gain full control over vulnerable servers. | 
| Privilege escalation <br> (Buffer overflow) | [CVE-2019-18634](CVE-2019-18634) | Sudo | A heap buffer overflow that leads to privilege <br>escalation on sudo <=1.8.25. | 
| RCE | [CVE-2020-7246](CVE-2020-7246) | qdPM | qdPM version 9.1 suffers from a remote code <br> execution vulnerability. | 
| RCE | [CVE-2019-16278](CVE-2019-16278) | nhttpd | Directory Traversal in the function http_verify allows an attacker to achieve remote code execution via a crafted HTTP request. | 
| RCE | [CVE-2019-15642](CVE-2019-15642) | Webmin | Webmin allows authenticated Remote Code <br> Execution via a crafted object. | 
| RCE | [CVE-2019-15107](CVE-2019-15107) | Webmin | The parameter old in <i>password_change.cgi</i> <br> contains a command injection vulnerability. | 
| RCE | [CVE-2019-12840](CVE-2019-12840) | Webmin | Any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges. | 
| RCE | [CVE-2019-11043](CVE-2019-11043) | PHP-FPM | In certain configurations of FPM setup it is possible to cause FPM module to write past allocated <br>buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote <br>code execution. In certain nginx + PHP-FPM configurations, the bug is possible to trigger from the outside. | 
| RCE | [CVE-2019-9624](CVE-2019-9624) | Webmin | Allows remote attackers to execute arbitrary <br> code by leveraging privileges to upload a crafted <br> .cgi file via the /updown/upload.cgi URI. | 
| RCE | [CVE-2019-7731](CVE-2019-7731) | MyWebSQL | MyWebSQL 3.7 has a remote code execution <br> vulnerability after an attacker writes shell code <br> into the database, and executes the Backup Database function with a .php filename for the backup's archive file | 
| SQL <br> Injection | [CVE-2020-9340](CVE-2020-9340) | eLection | fauzantrif eLection 2.0 has SQL Injection via the admin/ajax/op_kandidat.php *id* parameter. | 
| SQL <br> Injection | [CVE-2020-9268](CVE-2020-9268) | SO Planning | SoPlanning 1.45 is vulnerable to SQL Injection in the OrderBy clause, as demonstrated by the projets.php?order=nom_createur&by= substring. |
| Unauthorized File <br> Read | [CVE-2020-1938](CVE-2020-1938) | Apache<br>Tomcat | The AJP protocol is enabled by default allowing <br>untrusted clients to read web application files. | 
| User enumeration | [CVE-2018-15473](CVE-2018-15473) | OpenSSH | Vulnerability that could allow a remote attacker to determine if a user with the given name exists in <br>the system. | 
| XSS | [CVE-2019-13189](CVE-2019-13189) | Knowage<br>(FIWARE) | Knowage before 6.4 has Cross-site Scripting via <br> the ChangePwdServlet page, the parameters of <br> start_url and user_id are vulnerable |
| XXE | [CVE-2019-15641](CVE-2019-15641) | Webmin | Authenticated XXE allowing to retrieve local <br> file or discover internal networks with root rights. |

[comment]: <> (This is a comment, it will not be included)

<!---
Testing comment
-->

---
#### Fundings

* The work of Inês Martins has been supported by Fundação para a Ciência e Tecnologia [FCT](https://www.fct.pt), Portugal - 2021.04908.BD and partially funded by the SafeCities POCI-01-0247-FEDER-041435 project through [COMPETE 2020](https://www.compete2020.gov.pt) program.

* The work of João S. Resende has been supported by the EU H2020-SU-ICT-03-2018 Project No. 830929 [CyberSec4Europe](https://cybersec4europe.eu).

* The work of Patrícia R. Sousa has been supported by the Project “City Catalyst – Catalisador para cidades sustentáveis”, with reference POCI-01-0247-FEDER-046112, financed by Fundo Europeu de Desenvolvimento Regional (FEDER), through [COMPETE 2020](https://www.compete2020.gov.pt) and [Portugal 2020](https://portugal2020.pt) programs.

* The work of Simão Silva was partially funded by the SafeCities POCI-01-0247-FEDER-041435 project through [COMPETE 2020](https://www.compete2020.gov.pt) program.

* The work of João Gama was partially supported by the European Commission-funded project [Humane AI: Toward AI Systems That Augment and Empower Humans by Understanding Us, our Society and the World Around Us](https://cordis.europa.eu/project/id/820437) (grant # 820437). 

* The work of Luís Antunes has been supported by the Project “CNCS - Centro Nacional de Cibersegurança - Serviço de Gestão Alargada do Conhecimento Situacional e Operacional do Ciberespaço Nacional”, with reference POCI-05-5762-FSE-000229, financed by Agência para a Modernização Administrativa.

All the supports mentioned above are gratefully acknowledged.

