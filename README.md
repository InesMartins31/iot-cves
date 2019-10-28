IoT CVE's
===================================================


List
-----------


Attack type|CVE| Hardware / Software | Description
|---|---|---|---|
|MitM| [CVE-2019-6110 / CVE-2019-6111](CVE-2019-6111) |SCP - Secure Copy (openssh-clients package) | Vulnerability in OpenSSH that allows overwrite in files and could possible send more responses than required by user
|Privilege escalation|[CVE-2018-15473](CVE-2018-15473)|SSH|User enumeration: Vulnerability in OpenSSH that could allow a remote attacker to determine if a user with the given name exists in the system.
|Privilege escalation|[CVE-2019-14287](CVE-2019-14287)|Sudo|An attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. |