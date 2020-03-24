IoT CVEs
===================================================

| Attack type | CVE | Hardware / Software | Description |
|:----------------------------------------------------------------------:|:----------------------------------------------:|:-----------------------------------------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DoS | [CVE-2020-9283](CVE-2020-9283) | SSH (Go) | golang.org/x/crypto before <br> v0.0.0-20200220183623-bac4c82f6975<br>allows a malicious user to cause a panic <br> on an SSH server. |
| DoS | [CVE-2019-16279](CVE-2019-16279) | nhttpd | A memory error in the function SSL_accept allows an attacker to trigger a denial of service via a crafted HTTP request. |
| DoS (Out-of-Bounds read) | [CVE-2018-7182](CVE-2018-7182) | NTP | The ctl_getitem method in ntpd in ntp-4.2.8p6 <br> before 4.2.8p11 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted mode 6 packet with a ntpd instance. |
| Unauthorized File <br> Read | [CVE-2020-1938](CVE-2020-1938) | Apache<br>Tomcat | The AJP protocol is enabled by default allowing <br>untrusted clients to read web application files. |
| Out-of-Bounds read | [CVE-2019-17498](CVE-2019-17498) | Libssh2 | Libssh2 version 1.9.0 contains a remotely <br> triggerable out-of-bounds read, leading to denial of service or potentially to information disclosure. |
| Out-of-Bounds read | [CVE-2019-13115](CVE-2019-13115) | Libssh2 | Libssh2 version 1.8.2 contains a remotely <br> triggerable out-of-bounds read, potentially leading <br> to information disclosure. |
| XXE | [CVE-2019-15641](CVE-2019-15641) | Webmin | Authenticated XXE allowing to retrieve local <br> file or discover internal networks with root rights. |
| Password Hash Disclosure | [CVE-2019-13349](CVE-2019-13349) | Knowage<br>(FIWARE) | An authenticated user that accesses the users <br> page will obtain all user password hashes. |
| Disclosure of information about datasources including access passwords | [CVE-2019-13348](CVE-2019-13348) | Knowage<br>(FIWARE) | An authenticated user who accesses the <br> datasources page will gain access to any data <br> source credentials in cleartext, which includes databases. |
| XSS | [CVE-2019-13189](CVE-2019-13189) | Knowage<br>(FIWARE) | Knowage before 6.4 has Cross-site Scripting via <br> the ChangePwdServlet page, the parameters of <br> start_url and user_id are vulnerable |
| Access Control Bypass | [CVE-2019-13188](CVE-2019-13188) | Knowage<br>(FIWARE) | In Knowage through 6.1.1, an unauthenticated user can bypass access controls and access the entire application |
| MitM | [CVE-2019-6110 / CVE-2019-6111](CVE-2019-6111) | SCP - Secure Copy <br>(openssh-clients package) | Vulnerability in OpenSSH that allows overwrite <br> in files and could possible send more responses <br> than required by user. |
| Privilege escalation | [CVE-2019-14287](CVE-2019-14287) | Sudo | An attacker with access to a Runas ALL sudoer <br> account can bypass certain policy blacklists and <br> session PAM modules, and can cause incorrect <br> logging, by invoking sudo with a crafted user ID. |
| Privilege escalation | [CVE-2019-13272](CVE-2019-13272) | Linux kernel<br>(ptrace) | <i>Ptrace</i> mishandles the recording of the credentials <br> of a process that wants to create a ptrace relationship, which allows local users to obtain root <br>  access by leveraging certain scenarios with <br> a parent-child process relationship, where a parent drops privileges and calls <i>execve</i> (potentially allowing control by an attacker). |
| Privilege escalation | [CVE-2019-9891](CVE-2019-9891) | - | The function *getopt_simple* as described in Advanced Bash Scripting Guide allows privilege escalation and execution of commands when used in a shell script.
| Privilege escalation | [CVE-2019-8320](CVE-2019-8320) | Ruby | A Directory Traversal issue was discovered in RubyGems allowing to delete arbitrary files. |
| Privilege escalation / RCE | [CVE-2019-5736](CVE-2019-5736) | Docker | The vulnerability allows a malicious container (with minimal user interaction) to overwrite the host <br><i>runc</i> binary and thus gain root-level code execution on the host. |
| Privilege escalation | [CVE-2018-10933](CVE-2018-10933) | SSH | The <b>libssh</b>, a multiplatform library that supports <br> the SSH protocol, allows attackers to bypass authentication and gain full control over vulnerable servers. | 
| Privilege escalation <br> (Buffer overflow) | [CVE-2019-18634](CVE-2019-18634) | Sudo | A heap buffer overflow that leads to privilege <br>escalation on sudo <=1.8.25. |
| Buffer overflow / UAF | [CVE-2018-1000030](CVE-2018-1000030) | Python | Python 2.7.14 is vulnerable to a Heap-Buffer-Overflow as well as a Heap-Use-After-Free. <br> The vulnerability lies when multiply threads are handling large amounts of data. |
| Remote file reading | [CVE-2018-18778](CVE-2018-18778) | Mini_httpd | Mini_httpd before 1.30 lets remote users read arbitrary files. |
| User enumeration | [CVE-2018-15473](CVE-2018-15473) | OpenSSH | Vulnerability that could allow a remote attacker to determine if a user with the given name exists in <br>the system. |
| Improper file access | [CVE-2018-8712](CVE-2018-8712) | Webmin | Due to weak default configuration settings, <br>limited users have full access rights to the underlying system files, allowing the user to read sensitive data from the local system. |
| RCE | [CVE-2020-7246](CVE-2020-7246) | qdPM | qdPM version 9.1 suffers from a remote code <br> execution vulnerability. |
| RCE | [CVE-2019-16278](CVE-2019-16278) | nhttpd | Directory Traversal in the function http_verify allows an attacker to achieve remote code execution via a crafted HTTP request. |
| RCE | [CVE-2019-15642](CVE-2019-15642) | Webmin | Webmin allows authenticated Remote Code <br> Execution via a crafted object. |
| RCE | [CVE-2019-15107](CVE-2019-15107) | Webmin | The parameter old in <i>password_change.cgi</i> <br> contains a command injection vulnerability. |
| RCE | [CVE-2019-12840](CVE-2019-12840) | Webmin | Any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges. |
| RCE | [CVE-2019-11043](CVE-2019-11043) | PHP-FPM | In certain configurations of FPM setup it is possible to cause FPM module to write past allocated <br>buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote <br>code execution. In certain nginx + PHP-FPM configurations, the bug is possible to trigger from the outside. |
| RCE | [CVE-2019-9624](CVE-2019-9624) | Webmin | Allows remote attackers to execute arbitrary <br> code by leveraging privileges to upload a crafted <br> .cgi file via the /updown/upload.cgi URI. |
| RCE | [CVE-2019-7731](CVE-2019-7731) | MyWebSQL | MyWebSQL 3.7 has a remote code execution <br> vulnerability after an attacker writes shell code <br> into the database, and executes the Backup Database function with a .php filename for the backup's archive file |

[comment]: <> (This is a comment, it will not be included)

<!---
Testing comment
-->
