IoT CVEs
===================================================


List
-----------


Attack type|CVE| Hardware / Software | Description
|:---:|:---:|:---:|---|
| Out-of-Bounds read | [CVE-2019-17498](CVE-2019-17498) | Libssh2 | Libssh2 version 1.9.0 contains a remotely triggerable out-of-bounds read, leading to denial of service or potentially to information disclosure.|
| RCE | [CVE-2019-15642](CVE-2019-15642) | Webmin | Webmin allows authenticated Remote Code Execution via a crafted object.|
| RCE | [CVE-2019-15107](CVE-2019-15107) | Webmin | The parameter old in <i>password_change.cgi</i> contains a command injection vulnerability.|
| Privilege escalation | [CVE-2019-14287](CVE-2019-14287)| Sudo |An attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and <br> can cause incorrect logging, by invoking sudo with a crafted  <br>  user ID. |
| Privilege escalation | [CVE-2019-13272](CVE-2019-13272) | Linux kernel (ptrace) | <i>Ptrace</i> mishandles the recording of the credentials of a process <br> that wants to create a ptrace relationship, which allows local users <br> to obtain root access by leveraging certain scenarios with a  <br> parent-child process relationship, where a parent drops privileges and calls <i>execve</i> (potentially allowing control by an attacker).|
| Out-of-Bounds read | [CVE-2019-13115](CVE-2019-13115) | Libssh2 | Libssh2 version 1.8.2 contains a remotely triggerable out-of-bounds read, potentially leading to information disclosure. |
| RCE | [CVE-2019-12840](CVE-2019-12840) | Webmin | Any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges. |
| RCE |[CVE-2019-11043](CVE-2019-11043)| PHP-FPM | In certain configurations of FPM setup it is possible to cause FPM <br>  module to write past allocated buffers into the space reserved for  <br> FCGI protocol data, thus opening the possibility of remote code execution. In certain nginx + PHP-FPM configurations, the bug is possible to trigger from the outside.
| MitM | [CVE-2019-6110 / CVE-2019-6111](CVE-2019-6111) | SCP - Secure Copy (openssh-clients package) | Vulnerability in OpenSSH that allows overwrite in files and could possible send more responses than required by user. |
| Privilege escalation / RCE | [CVE-2019-5736](CVE-2019-5736) | Docker | The vulnerability allows a malicious container (with minimal user interaction) to overwrite the host <i>runc</i> binary and thus gain root-level code execution on the host.|
| Remote file reading | [CVE-2018-18778](CVE-2018-18778) | Mini_httpd | Mini_httpd before 1.30 lets remote users read arbitrary files.|  
| User enumeration | [CVE-2018-15473](CVE-2018-15473)| OpenSSH | Vulnerability that could allow a remote attacker to determine if a user with the given name exists in the system.|
| Privilege escalation | [CVE-2018-10933](CVE-2018-10933) | SSH | The <b>libssh</b>, a multiplatform library that supports the SSH protocol, allows attackers to bypass authentication and gain full control over vulnerable servers.| 


[comment]: <> (This is a comment, it will not be included)

<!---
Testing comment
-->
