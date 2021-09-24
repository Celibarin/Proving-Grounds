# Enumeration
## Nmap
### Inital Scan
Command
```
nmap -A -vv -oA enum/nmap-initial 192.168.83.105
```

Output
```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIa7leEeVssjdrJAMl1xs+qCC7DvEgvhDmYxn7oFKkzQdWQXNwPDaf19b+8uxImEAQ3uRXYg56MItfQ54pTuDpJSuuSfCXyqH9/o5S+gugCgkGiWRTlyXAmCe4uM4ZZD09yChsJ0LdPKvqM19l5o+8KCBuXAGOX7Co60oUpD3+xINAS/XQYFdY1RARpIsuzd3qUHkeKJvGp2hbI6b2bgfcjTcPgBaLKLMa6OZ208whcHdYwJdOnc2m3mi2o9v+ETK+P8exJ1/DTIYLLVlo0BPMqlCE2R4JyEfp8RQeggq42yHOMmBI6pQ/BhClgheiPDhF+hQLNafLgkLeHv625eFq7V8bwi2Uy7/NV8jip1FobFhaT2L/MiRHnx7my4Cxk0BzoAvj0fOzOXouT5rMon6o14x/HTQBqORFhLvTNkCnPE0nen8ohQ05R0oWFiVwH74OaLHvwmzUuy8d1Wln5rW26q+UjZy1AIGpRHvyfEV5dzmB0ujnrE8Io702tIb/ssM=
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLFrQmyRArhVBZ7HJi6W3YN/7sFuTBg5RLoffgVyCRaVpqj/VAwL3c85iE7s1x61oRu7CiVIvzOcYAMh5BfOjuI=
|   256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWYiSpSV5PFfFK8fw7UZ1MAMHej2xBONdUi5CSr7huF
80/tcp   open  http    syn-ack Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-generator: WordPress 5.5.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-title: Retro Gamming &#8211; Just another WordPress site
3306/tcp open  mysql?  syn-ack
| fingerprint-strings: 
|   NULL, RPCCheck, SIPOptions, SMBProgNeg: 
|_    Host '192.168.49.83' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '192.168.49.83' is not allowed to connect to this MariaDB server
5000/tcp open  http    syn-ack Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5
|_http-title: 404 Not Found
```

### Full Scan
Command
```
nmap -A -vv -p- -oA enum/nmap-full 192.168.83.105
```

Output
```
PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIa7leEeVssjdrJAMl1xs+qCC7DvEgvhDmYxn7oFKkzQdWQXNwPDaf19b+8uxImEAQ3uRXYg56MItfQ54pTuDpJSuuSfCXyqH9/o5S+gugCgkGiWRTlyXAmCe4uM4ZZD09yChsJ0LdPKvqM19l5o+8KCBuXAGOX7Co60oUpD3+xINAS/XQYFdY1RARpIsuzd3qUHkeKJvGp2hbI6b2bgfcjTcPgBaLKLMa6OZ208whcHdYwJdOnc2m3mi2o9v+ETK+P8exJ1/DTIYLLVlo0BPMqlCE2R4JyEfp8RQeggq42yHOMmBI6pQ/BhClgheiPDhF+hQLNafLgkLeHv625eFq7V8bwi2Uy7/NV8jip1FobFhaT2L/MiRHnx7my4Cxk0BzoAvj0fOzOXouT5rMon6o14x/HTQBqORFhLvTNkCnPE0nen8ohQ05R0oWFiVwH74OaLHvwmzUuy8d1Wln5rW26q+UjZy1AIGpRHvyfEV5dzmB0ujnrE8Io702tIb/ssM=
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLFrQmyRArhVBZ7HJi6W3YN/7sFuTBg5RLoffgVyCRaVpqj/VAwL3c85iE7s1x61oRu7CiVIvzOcYAMh5BfOjuI=
|   256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWYiSpSV5PFfFK8fw7UZ1MAMHej2xBONdUi5CSr7huF
80/tcp    open  http        syn-ack Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-generator: WordPress 5.5.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-title: Retro Gamming &#8211; Just another WordPress site
3306/tcp  open  mysql?      syn-ack
| fingerprint-strings: 
|   LDAPBindReq, NULL: 
|_    Host '192.168.49.83' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '192.168.49.83' is not allowed to connect to this MariaDB server
5000/tcp  open  http        syn-ack Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5
|_http-title: 404 Not Found
13000/tcp open  http        syn-ack nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0
|_http-title: Login V14
36445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
```

## Port 80
>![[Pasted image 20210528124921.png]]
### Nikto
Command
```
nikto -h http://192.168.83.105 -o enum/nikto.txt
```

Output
```
+ Server: Apache/2.4.46 (Unix) PHP/7.4.10
+ Retrieved x-powered-by header: PHP/7.4.10
+ RFC-1918 IP address found in the 'link' header. The IP is "192.168.120.55".
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'link' found, with contents: <http://192.168.120.55/index.php/wp-json/>; rel="https://api.w.org/"
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'x-redirect-by' found, with contents: WordPress
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var
+ OSVDB-637: Enumeration of users is possible by requesting ~username (responds with 'Forbidden' for users, 'not found' for non-existent users).
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ Cookie wordpress_test_cookie created without the httponly flag
+ OSVDB-3268: /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information
+ /wp-login.php: Wordpress login found
+ 7917 requests: 0 error(s) and 21 item(s) reported on remote host
+ End Time:           2021-05-28 12:45:06 (GMT-5) (390 seconds)
```

### GoBuster
Command
```
gobuster dir -u http://192.168.83.105 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster.txt
```

Output
```
/wp-content           (Status: 301) [Size: 241] [--> http://192.168.83.105/wp-content/]
/wordpress            (Status: 301) [Size: 240] [--> http://192.168.83.105/wordpress/] 
/wp-includes          (Status: 301) [Size: 242] [--> http://192.168.83.105/wp-includes/]
/wp-admin             (Status: 301) [Size: 239] [--> http://192.168.83.105/wp-admin/] 
```
 
---

# Vulnerabilities


---

# Privilege Escalation


---

# Loot
## User
> 
## Root/Admin
>