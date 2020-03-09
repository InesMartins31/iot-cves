IoT CVEs
===================================================


List
-----------

Attack type|CVE| Hardware / Software | Description
|:---:|:---:|:---:|---|
| DoS | [CVE-2020-9283](CVE-2020-9283) | SSH (Go) | golang.org/x/crypto before <br> v0.0.0-20200220183623-bac4c82f6975  <br/>  allows a malicious user to cause a panic on an SSH server.
| RCE | [CVE-2020-7246](CVE-2020-7246) | qdPM |qdPM version 9.1 suffers from a remote code <br> execution vulnerability.|
| Unauthorized File <br> Read | [CVE-2020-1938](CVE-2020-1938) | Apache <br> Tomcat | The AJP protocol is enabled by default allowing untrusted clients to read web application files. |
| Buffer overflow | [CVE-2019-18634](CVE-2019-18634) | Sudo | A heap buffer overflow that leads to privilege escalation <br> on sudo <=1.8.25. |
| Out-of-Bounds read | [CVE-2019-17498](CVE-2019-17498) | Libssh2 | Libssh2 version 1.9.0 contains a remotely triggerable <br> out-of-bounds read, leading to denial of service or <br> potentially to information disclosure.|
| RCE | [CVE-2019-15642](CVE-2019-15642) | Webmin | Webmin allows authenticated Remote Code Execution via <br>  a crafted object.|
| RCE | [CVE-2019-15107](CVE-2019-15107) | Webmin | The parameter old in <i>password_change.cgi</i> contains a command injection vulnerability.|
| Privilege escalation | [CVE-2019-14287](CVE-2019-14287)| Sudo |An attacker with access to a Runas ALL sudoer <br/> account can bypass certain policy blacklists and  <br/> session PAM modules, and can cause incorrect <br/> logging, by invoking sudo with a crafted user ID. |
| Password Hash Disclosure | [CVE-2019-13349](CVE-2019-13349) | FIWARE - Knowage | An authenticated user that accesses the users page will obtain all user password hashes.|
| Disclosure of information about datasources including access passwords| [CVE-2019-13348](CVE-2019-13348)| FIWARE - Knowage | An authenticated user who accesses the datasources page will gain access to any data source credentials in cleartext, which includes databases. |
| Privilege escalation | [CVE-2019-13272](CVE-2019-13272) | Linux kernel (ptrace) | <i>Ptrace</i> mishandles the recording of the credentials  <br>  of a process that wants to create a ptrace relationship, <br>  which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls <i>execve</i> (potentially allowing control by an attacker).|
| Out-of-Bounds read | [CVE-2019-13115](CVE-2019-13115) | Libssh2 | Libssh2 version 1.8.2 contains a remotely triggerable  <br/> out-of-bounds read, potentially leading to information disclosure. |
| RCE | [CVE-2019-12840](CVE-2019-12840) | Webmin | Any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges. |
| RCE |[CVE-2019-11043](CVE-2019-11043)| PHP-FPM | In certain configurations of FPM setup it is possible  <br>  to cause FPM module to write past allocated buffers <br> into the space reserved for FCGI protocol data, thus <br/> opening the possibility of remote code execution. In <br/> certain nginx + PHP-FPM configurations, the bug is <br/> possible to trigger from the outside.
| RCE | [CVE-2019-9624](CVE-2019-9624) | Webmin | Allows remote attackers to execute arbitrary code by leveraging privileges to upload a crafted .cgi file via the /updown/upload.cgi URI.|
| RCE | [CVE-2019-7731](CVE-2019-7731) | MyWebSQL | MyWebSQL 3.7 has a remote code execution (RCE) vulnerability after an attacker writes shell code into the database, and executes the Backup Database function with a .php filename for the backup's archive file|
| MitM | [CVE-2019-6110 / CVE-2019-6111](CVE-2019-6111) | SCP - Secure Copy (openssh-clients package) | Vulnerability in OpenSSH that allows overwrite in files and could possible send more responses than required by user. |
| Privilege escalation / RCE | [CVE-2019-5736](CVE-2019-5736) | Docker | The vulnerability allows a malicious container (with minimal user interaction) to overwrite the host <i>runc</i> binary and thus gain root-level code execution on the host.|
| Buffer overflow / UAF | [CVE-2018-1000030](CVE-2018-1000030) | Python | Python 2.7.14 is vulnerable to a Heap-Buffer-Overflow as well as a Heap-Use-After-Free. The vulnerability lies when multiply threads are handling large amounts of data.
| Remote file reading | [CVE-2018-18778](CVE-2018-18778) | Mini_httpd | Mini_httpd before 1.30 lets remote users read arbitrary files.|  
| User enumeration | [CVE-2018-15473](CVE-2018-15473)| OpenSSH | Vulnerability that could allow a remote attacker to determine if a user with the given name exists in the system.|
| Privilege escalation | [CVE-2018-10933](CVE-2018-10933) | SSH | The <b>libssh</b>, a multiplatform library that supports the SSH protocol, allows attackers to bypass authentication and gain full control over vulnerable servers.|   
| DoS (Out-of-Bounds read) | [CVE-2018-7182](CVE-2018-7182) | NTP | The ctl_getitem method in ntpd in ntp-4.2.8p6 before 4.2.8p11 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted mode 6 packet with a ntpd instance. | 

[comment]: <> (This is a comment, it will not be included)

<!---
Testing comment
-->