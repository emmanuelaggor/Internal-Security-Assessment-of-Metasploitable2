# Internal Security Assessment of Metasploitable2
**Client:** ParoCyber  
**Course:** ParoCyber - Ethical Hacking  
**Assessor:** Emmanuel Selasie Aggor 
**Attacker Machine:** Kali Linux  
**Target Machine:** Metasploitable2  
**Assessment Duration:** 1 Week  
**Date:** June 2026  
**Classification:** Confidential

---

## 1.1 Objective
 
Identify as much information as possible about the target system including its IP address, open ports, running services, service versions, and hosted web applications.

---
 
## 1.2 Network Discovery
 
### Tool Used
`nmap` `ip a` – Host Discovery Scan
 
### Command
```bash
ip a
nmap -sn 192.168.56.0/24
```
 
### Result
 
| Field            | Value              |
|------------------|--------------------|
| Attacker IP      | 192.168.56.102     |
| Target IP        | 192.168.56.103     |
| Network Range    | 192.168.56.0/24    |
| MAC Address      | 08:00:27:4F:2A:5E  |
| Host Status      | Up                 |
 

**Screenshot:** ![network discovery](screenshots/networkdiscovery.png)

---

## 1.2 Port Scanning

**Tool Used:** `nmap` – Full Port Scan with Version Detection

**Command:**
```bash
nmap -sV -sC -p- 192.168.56.103 -oN phase1_portscan.txt
```

**Open Ports Discovered:**

| Port      | State | Service               | Version                                        |
|-----------|-------|-----------------------|------------------------------------------------|
| 21/tcp    | Open  | FTP                   | vsftpd 2.3.4 (anonymous login allowed)         |
| 22/tcp    | Open  | SSH                   | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)  |
| 23/tcp    | Open  | Telnet                | Linux telnetd                                  |
| 25/tcp    | Open  | SMTP                  | Postfix smtpd                                  |
| 53/tcp    | Open  | DNS                   | ISC BIND 9.4.2                                 |
| 80/tcp    | Open  | HTTP                  | Apache httpd 2.2.8 (Ubuntu DAV/2)              |
| 111/tcp   | Open  | RPCbind               | 2 (RPC #100000)                                |
| 139/tcp   | Open  | NetBIOS-SSN           | Samba smbd 3.X - 4.X (workgroup: WORKGROUP)   |
| 445/tcp   | Open  | SMB                   | Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)|
| 512/tcp   | Open  | exec                  | netkit-rsh rexecd                              |
| 513/tcp   | Open  | login                 | rlogind                                        |
| 514/tcp   | Open  | shell                 | Netkit rshd                                    |
| 1099/tcp  | Open  | Java RMI              | GNU Classpath grmiregistry                     |
| 1524/tcp  | Open  | bindshell (Backdoor)  | Metasploitable root shell                      |
| 2049/tcp  | Open  | NFS                   | 2-4 (RPC #100003)                              |
| 2121/tcp  | Open  | FTP (Alt)             | ProFTPD 1.3.1                                  |
| 3306/tcp  | Open  | MySQL                 | MySQL 5.0.51a-3ubuntu5                         |
| 3632/tcp  | Open  | distccd               | distccd v1 (GNU 4.2.4 Ubuntu)                  |
| 5432/tcp  | Open  | PostgreSQL            | PostgreSQL DB 8.3.0 - 8.3.7                   |
| 5900/tcp  | Open  | VNC                   | VNC Protocol 3.3                               |
| 6000/tcp  | Open  | X11                   | Access Denied                                  |
| 6667/tcp  | Open  | IRC                   | UnrealIRCd                                     |
| 6697/tcp  | Open  | IRC (SSL)             | UnrealIRCd                                     |
| 8009/tcp  | Open  | AJP13                 | Apache Jserv Protocol v1.3                     |
| 8180/tcp  | Open  | HTTP (Alt)            | Apache Tomcat/Coyote JSP engine 1.1            |
| 8787/tcp  | Open  | DRb                   | Ruby DRb RMI (Ruby 1.8)                        |
| 45054/tcp | Open  | nlockmgr              | 1-4 (RPC #100021)                              |
| 45407/tcp | Open  | mountd                | 1-3 (RPC #100005)                              |
| 53103/tcp | Open  | status                | 1 (RPC #100024)                                |
| 54882/tcp | Open  | Java RMI              | GNU Classpath grmiregistry                     |

**Screenshot:** ![full port scan](screenshots/fullportscanwithversion.png)

---

## 2.4 Service Enumeration

#### FTP – Port 21 (vsftpd 2.3.4)

**Command:**
```bash
nmap -sV -p 21 --script=ftp-anon,ftp-syst 192.168.56.103
```

**Findings:**
- Version: vsftpd 2.3.4 
- Anonymous FTP login: **Allowed** (FTP code 230 confirmed by scan)
- Connected client logged in as: `ftp`
- Connection type: plaintext (no encryption on control or data connections)
- Session timeout: 300 seconds
- Known backdoor: CVE-2011-2523 — vsftpd 2.3.4 backdoor allows unauthenticated remote command execution via a smiley-face `:)` in the username

**Screenshot:** ![port21 scan](screenshots/serviceenumerationftpport21.png)

---

## SSH – Port 22 (OpenSSH 4.7p1)

**Command:**
```bash
nmap -p 22 --script=ssh-hostkey 192.168.56.103
```

**Findings:**
- Version: OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) — released 2007, critically outdated
- DSA host key (1024-bit): `60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd`
- RSA host key (2048-bit): `56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3`
- Susceptible to brute-force attacks — no rate limiting configured

**Screenshot:** ![port22 scan](screenshots/serviceenumerationsshport22.png)

---

## SMB – Port 445 (Samba 3.0.20)

**Command:**
```bash
nmap -p 445 --script=smb-os-discovery 192.168.56.103
```

**Findings:**
- OS: Unix (Samba 3.0.20-Debian)
- Computer Name: `metasploitable`
- NetBIOS Name: `METASPLOITABLE`
- Domain: `localdomain`
- FQDN: `metasploitable.localdomain`
- System time: 2026-06-10T14:38:56-04:00
- Message signing: **disabled** (dangerous — enables relay attacks)
- SMB2: negotiation failed (only SMBv1 supported)
- Vulnerable to CVE-2007-2447 (Samba usermap_script — unauthenticated RCE)

**Screenshot:** ![port445 scan](screenshots/serviceenumerationsmbport445.png)

---

## HTTP – Port 80 (Apache 2.2.8)

**Command:**
```bash
nmap -p 80 --script=http-title,http-headers 192.168.56.103
```

**Findings:**
- Server: Apache/2.2.8 (Ubuntu) DAV/2
- Page title: `Metasploitable2 - Linux`
- WebDAV enabled — potential file upload vector
- Multiple vulnerable web applications hosted

**Screenshot:** ![port80 scan](screenshots/serviceenumerationhttpport80.png)
