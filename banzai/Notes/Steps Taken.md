# Proving Grounds - bansai - 192.168.143.56

# Enumeration
## Nmap
### Inital Scan
Command
```
nmap -A -vv -Pn -oA enum/nmap-initial 192.168.143.56
```

Output
```
PORT     STATE  SERVICE    REASON       VERSION                                                                                                                                                                                              
20/tcp   closed ftp-data   conn-refused                                                                                                                                                                                                      
21/tcp   open   ftp        syn-ack      vsftpd 3.0.3                                                                                                                                                                                         
22/tcp   open   ssh        syn-ack      OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)                                                                                                                                                        
| ssh-hostkey:                                                                                                                                                                                                                               
|   2048 ba:3f:68:15:28:86:36:49:7b:4a:84:22:68:15:cc:d1 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCybLhvDM6WN4Um6RXgjUecDnd4j/h14PyuqRaLgWRDaQlyWakjDG21gvvltRKiKfDvTHXBS+gDAbGLEmD58g41NE1ocCf5uGtmn79Z3BOR+7BdP1PETWb4a9GR+PdrvXpD16mIHZORhs4RAkeBpexcKOkFXCFatjymyVAcNB8E+Twh879lb55hxEz9cLlA8RAiPPf
uW5S7nCRhw7xEi9mdtlvURCFNLb7eCGDUOQu5op2r6XpxZi0eYXJVde/13AiYxvACA2sRoMDCQwIYLhXwpA1Z7LseLxSmMHwyDXrxCU9xDJ+HL9EaHozBdHCOnnuHqPtb5EPZ3/JTg3qnS0dR                                                                                            
|   256 2d:ec:3f:78:31:c3:d0:34:5e:3f:e7:6b:77:b5:61:09 (ECDSA)                                                                                                                                                                              
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNRPQTMD0l4TqSTmzmck9Rhq1ULCN0ErNvXipXv1HBKoRUgdbdwxhFerbDTxxJYd+12RFoZgNNUDZmSH7+PGvpo=                                                                           
|   256 4f:61:5c:cc:b0:1f:be:b4:eb:8f:1c:89:71:04:f0:aa (ED25519)                                                                                                                                                                            
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpzo9sh+q0DgrOjD1plfJ9xj9zIjezUBGWzdNlde40M                                                                                                                                                           
25/tcp   open   smtp       syn-ack      Postfix smtpd                                                                                                                                                                                        
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,                                                                                                       
| ssl-cert: Subject: commonName=banzai                                                                                                                                                                                                       
| Subject Alternative Name: DNS:banzai                                                                                                                                                                                                       
| Issuer: commonName=banzai                                                                                                                                                                                                                  
| Public Key type: rsa                                                                                                                                                                                                                       
| Public Key bits: 2048                                                                                                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                                                                                                               
| Not valid before: 2020-06-04T14:30:35                                                                                                                                                                                                      
| Not valid after:  2030-06-02T14:30:35                                                                                                                                                                                                      
| MD5:   3b28 61f1 af62 d273 0a3d dc1f f716 60c0                                                                                                                                                                                             
| SHA-1: 16d4 7b5e b6f4 0cc5 e581 da6c 563d edcf 3f8f 0072                                                                                                                                                                                   
| -----BEGIN CERTIFICATE-----                                                                                                                                                                                                                
| MIICxTCCAa2gAwIBAgIJAOwMttjJ91fXMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV                                                                                                                                                                           
| BAMMBmJhbnphaTAeFw0yMDA2MDQxNDMwMzVaFw0zMDA2MDIxNDMwMzVaMBExDzAN                                                                                                                                                                           
| BgNVBAMMBmJhbnphaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANSD                                                                                                                                                                           
| KNoh+InV/GzD8Fn6TPapcKXOWc7mPwvV70p4Qm5hPSEbvH83yFPX56qQQnKmOUlE                                                                                                                                                                           
| hIhXxMapYJGLMmL+ipsWXXz/6s5y28Mfk8XdhwvzJ/pCfawDPnYwff7jtfgz5qlf                                                                                                                                                                           
| JHLULDr+fjXLPlyefiUEj8kpmZCHKhxra5MG/M6urW72faf8x4XUsi7y/qJQoBeH                                                                                                                                                                           
| nKf6n0upVtPp1FLKSkJgfBouSDDPy0KBTdKs9YjnFtcDJt6+Ll0m9Wj4rnF8m/67                                                                                                                                                                           
| oguSxsqd94gPpdnUo4mKmqnwNq/kdC/gopIOjxo44043O11OQd+x97Wy+GrqPa4W                                                                                                                                                                           
| Zw8uwxc2FnQe3pevrssCAwEAAaMgMB4wCQYDVR0TBAIwADARBgNVHREECjAIggZi                                                                                                                                                                           
| YW56YWkwDQYJKoZIhvcNAQELBQADggEBAJUjJMMvV12i1Kzh5bTrGIW3AF5eJtZz                                                                                                                                                                           
| CQCIgw6asjV5aiJGx58BFox6LkN9JzZsiQKNrLtA62FnAj1LWGd1+dt+fPNayiOG                                                                                                                                                                           
| ZjLeZfXBN4dPOlrT9YU+gyqJJWEuMcvwzGMMqa4W/WW9E6+Q9o3w+lhdJhZTMzsq                                                                                                                                                                           
| 11M/CGd5mjZHa1hMQNxTef8BpHn6yGOi9k6PncGHIUSapxcy3+7HQXJEap65m8eT                                                                                                                                                                           
| jPZdt1hXouOZsNbtQkW32oiQ+4snDmjgbvoqZKF68/UV/3if5S3F6MCI7go8i3yu                                                                                                                                                                           
| SHIIOYrPzXEb5U8Vw8UDUEn/4WV3h9j4ouZHDibV2gRs6VPThzR7SdE=                                                                                                                                                                                   
|_-----END CERTIFICATE-----                                                                                                                                                                                                                  
|_ssl-date: TLS randomness does not represent time
5432/tcp open   postgresql syn-ack      PostgreSQL DB 9.6.4 - 9.6.6 or 9.6.13 - 9.6.17                                                                                                                                                       
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Issuer: commonName=banzai
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-06-04T14:30:35
| Not valid after:  2030-06-02T14:30:35
| MD5:   3b28 61f1 af62 d273 0a3d dc1f f716 60c0
| SHA-1: 16d4 7b5e b6f4 0cc5 e581 da6c 563d edcf 3f8f 0072
| -----BEGIN CERTIFICATE-----
| MIICxTCCAa2gAwIBAgIJAOwMttjJ91fXMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBmJhbnphaTAeFw0yMDA2MDQxNDMwMzVaFw0zMDA2MDIxNDMwMzVaMBExDzAN
| BgNVBAMMBmJhbnphaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANSD
| KNoh+InV/GzD8Fn6TPapcKXOWc7mPwvV70p4Qm5hPSEbvH83yFPX56qQQnKmOUlE
| hIhXxMapYJGLMmL+ipsWXXz/6s5y28Mfk8XdhwvzJ/pCfawDPnYwff7jtfgz5qlf
| JHLULDr+fjXLPlyefiUEj8kpmZCHKhxra5MG/M6urW72faf8x4XUsi7y/qJQoBeH
| nKf6n0upVtPp1FLKSkJgfBouSDDPy0KBTdKs9YjnFtcDJt6+Ll0m9Wj4rnF8m/67
| oguSxsqd94gPpdnUo4mKmqnwNq/kdC/gopIOjxo44043O11OQd+x97Wy+GrqPa4W
| Zw8uwxc2FnQe3pevrssCAwEAAaMgMB4wCQYDVR0TBAIwADARBgNVHREECjAIggZi
| YW56YWkwDQYJKoZIhvcNAQELBQADggEBAJUjJMMvV12i1Kzh5bTrGIW3AF5eJtZz
| CQCIgw6asjV5aiJGx58BFox6LkN9JzZsiQKNrLtA62FnAj1LWGd1+dt+fPNayiOG
| ZjLeZfXBN4dPOlrT9YU+gyqJJWEuMcvwzGMMqa4W/WW9E6+Q9o3w+lhdJhZTMzsq
| 11M/CGd5mjZHa1hMQNxTef8BpHn6yGOi9k6PncGHIUSapxcy3+7HQXJEap65m8eT
| jPZdt1hXouOZsNbtQkW32oiQ+4snDmjgbvoqZKF68/UV/3if5S3F6MCI7go8i3yu
| SHIIOYrPzXEb5U8Vw8UDUEn/4WV3h9j4ouZHDibV2gRs6VPThzR7SdE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
8080/tcp open   http       syn-ack      Apache httpd 2.4.25 
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: 403 Forbidden
Service Info: Hosts:  banzai.offseclabs.com, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Full Scan
Command
```
nmap -A -vv -p- -Pn -oA enum/nmap-full 192.168.143.56
```

Output
```
PORT     STATE  SERVICE    REASON       VERSION                                                                                                                                                                                              
20/tcp   closed ftp-data   conn-refused                                                                                                                                                                                                      
21/tcp   open   ftp        syn-ack      vsftpd 3.0.3                                                                                                                                                                                         
22/tcp   open   ssh        syn-ack      OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)                                                                                                                                                        
| ssh-hostkey:                                                                                                                                                                                                                               
|   2048 ba:3f:68:15:28:86:36:49:7b:4a:84:22:68:15:cc:d1 (RSA)                                                                                                                                                                               
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCybLhvDM6WN4Um6RXgjUecDnd4j/h14PyuqRaLgWRDaQlyWakjDG21gvvltRKiKfDvTHXBS+gDAbGLEmD58g41NE1ocCf5uGtmn79Z3BOR+7BdP1PETWb4a9GR+PdrvXpD16mIHZORhs4RAkeBpexcKOkFXCFatjymyVAcNB8E+Twh879lb55hxEz9cLlA8RAiPPf
uW5S7nCRhw7xEi9mdtlvURCFNLb7eCGDUOQu5op2r6XpxZi0eYXJVde/13AiYxvACA2sRoMDCQwIYLhXwpA1Z7LseLxSmMHwyDXrxCU9xDJ+HL9EaHozBdHCOnnuHqPtb5EPZ3/JTg3qnS0dR                                                                                            
|   256 2d:ec:3f:78:31:c3:d0:34:5e:3f:e7:6b:77:b5:61:09 (ECDSA)                                                                                                                                                                              
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNRPQTMD0l4TqSTmzmck9Rhq1ULCN0ErNvXipXv1HBKoRUgdbdwxhFerbDTxxJYd+12RFoZgNNUDZmSH7+PGvpo=                                                                           
|   256 4f:61:5c:cc:b0:1f:be:b4:eb:8f:1c:89:71:04:f0:aa (ED25519)                                                                                                                                                                            
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpzo9sh+q0DgrOjD1plfJ9xj9zIjezUBGWzdNlde40M                                                                                                                                                           
25/tcp   open   smtp       syn-ack      Postfix smtpd                                                                                                                                                                                        
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,                                                                                                       
| ssl-cert: Subject: commonName=banzai                                                                                                                                                                                                       
| Subject Alternative Name: DNS:banzai                                                                                                                                                                                                       
| Issuer: commonName=banzai                                                                                                                                                                                                                  
| Public Key type: rsa                                                                                                                                                                                                                       
| Public Key bits: 2048                                                                                                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                                                                                                               
| Not valid before: 2020-06-04T14:30:35                                                                                                                                                                                                      
| Not valid after:  2030-06-02T14:30:35                                                                                                                                                                                                      
| MD5:   3b28 61f1 af62 d273 0a3d dc1f f716 60c0                                                                                                                                                                                             
| SHA-1: 16d4 7b5e b6f4 0cc5 e581 da6c 563d edcf 3f8f 0072                                                                                                                                                                                   
| -----BEGIN CERTIFICATE-----                                                                                                                                                                                                                
| MIICxTCCAa2gAwIBAgIJAOwMttjJ91fXMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV                                                                                                                                                                           
| BAMMBmJhbnphaTAeFw0yMDA2MDQxNDMwMzVaFw0zMDA2MDIxNDMwMzVaMBExDzAN                                                                                                                                                                           
| BgNVBAMMBmJhbnphaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANSD                                                                                                                                                                           
| KNoh+InV/GzD8Fn6TPapcKXOWc7mPwvV70p4Qm5hPSEbvH83yFPX56qQQnKmOUlE                                                                                                                                                                           
| hIhXxMapYJGLMmL+ipsWXXz/6s5y28Mfk8XdhwvzJ/pCfawDPnYwff7jtfgz5qlf                                                                                                                                                                           
| JHLULDr+fjXLPlyefiUEj8kpmZCHKhxra5MG/M6urW72faf8x4XUsi7y/qJQoBeH                                                                                                                                                                           
| nKf6n0upVtPp1FLKSkJgfBouSDDPy0KBTdKs9YjnFtcDJt6+Ll0m9Wj4rnF8m/67                                                                                                                                                                           
| oguSxsqd94gPpdnUo4mKmqnwNq/kdC/gopIOjxo44043O11OQd+x97Wy+GrqPa4W                                                                                                                                                                           
| Zw8uwxc2FnQe3pevrssCAwEAAaMgMB4wCQYDVR0TBAIwADARBgNVHREECjAIggZi
| YW56YWkwDQYJKoZIhvcNAQELBQADggEBAJUjJMMvV12i1Kzh5bTrGIW3AF5eJtZz
| CQCIgw6asjV5aiJGx58BFox6LkN9JzZsiQKNrLtA62FnAj1LWGd1+dt+fPNayiOG
| ZjLeZfXBN4dPOlrT9YU+gyqJJWEuMcvwzGMMqa4W/WW9E6+Q9o3w+lhdJhZTMzsq
| 11M/CGd5mjZHa1hMQNxTef8BpHn6yGOi9k6PncGHIUSapxcy3+7HQXJEap65m8eT
| jPZdt1hXouOZsNbtQkW32oiQ+4snDmjgbvoqZKF68/UV/3if5S3F6MCI7go8i3yu
| SHIIOYrPzXEb5U8Vw8UDUEn/4WV3h9j4ouZHDibV2gRs6VPThzR7SdE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5432/tcp open   postgresql syn-ack      PostgreSQL DB 9.6.4 - 9.6.6 or 9.6.13 - 9.6.17                                                                                                                                                [0/262]
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Issuer: commonName=banzai
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-06-04T14:30:35
| Not valid after:  2030-06-02T14:30:35
| MD5:   3b28 61f1 af62 d273 0a3d dc1f f716 60c0
| SHA-1: 16d4 7b5e b6f4 0cc5 e581 da6c 563d edcf 3f8f 0072
| -----BEGIN CERTIFICATE-----
| MIICxTCCAa2gAwIBAgIJAOwMttjJ91fXMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBmJhbnphaTAeFw0yMDA2MDQxNDMwMzVaFw0zMDA2MDIxNDMwMzVaMBExDzAN
| BgNVBAMMBmJhbnphaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANSD
| KNoh+InV/GzD8Fn6TPapcKXOWc7mPwvV70p4Qm5hPSEbvH83yFPX56qQQnKmOUlE
| hIhXxMapYJGLMmL+ipsWXXz/6s5y28Mfk8XdhwvzJ/pCfawDPnYwff7jtfgz5qlf
| JHLULDr+fjXLPlyefiUEj8kpmZCHKhxra5MG/M6urW72faf8x4XUsi7y/qJQoBeH
| nKf6n0upVtPp1FLKSkJgfBouSDDPy0KBTdKs9YjnFtcDJt6+Ll0m9Wj4rnF8m/67
| oguSxsqd94gPpdnUo4mKmqnwNq/kdC/gopIOjxo44043O11OQd+x97Wy+GrqPa4W
| Zw8uwxc2FnQe3pevrssCAwEAAaMgMB4wCQYDVR0TBAIwADARBgNVHREECjAIggZi
| YW56YWkwDQYJKoZIhvcNAQELBQADggEBAJUjJMMvV12i1Kzh5bTrGIW3AF5eJtZz
| CQCIgw6asjV5aiJGx58BFox6LkN9JzZsiQKNrLtA62FnAj1LWGd1+dt+fPNayiOG
| ZjLeZfXBN4dPOlrT9YU+gyqJJWEuMcvwzGMMqa4W/WW9E6+Q9o3w+lhdJhZTMzsq
| 11M/CGd5mjZHa1hMQNxTef8BpHn6yGOi9k6PncGHIUSapxcy3+7HQXJEap65m8eT
| jPZdt1hXouOZsNbtQkW32oiQ+4snDmjgbvoqZKF68/UV/3if5S3F6MCI7go8i3yu
| SHIIOYrPzXEb5U8Vw8UDUEn/4WV3h9j4ouZHDibV2gRs6VPThzR7SdE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
8080/tcp open   http       syn-ack      Apache httpd 2.4.25 
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: 403 Forbidden
8295/tcp open   http       syn-ack      Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Banzai
Service Info: Hosts:  banzai.offseclabs.com, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 8080

![](../Attachments/Pasted%20image%2020211014194429.png)

### Nikto
Command
```
nikto -h http://192.168.143.56:8080 -o enum/nikto-8080.txt
```

Output
```
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ All CGI directories 'found', use '-C none' to test none
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26547 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-10-14 20:26:47 (GMT-5) (1002 seconds)
---------------------------------------------------------------------------
```

### GoBuster
Command
```
gobuster dir -u http://192.168.143.56:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster-8080.txt
```

Output
```
Wildcard error
```

## Port 8295

![](../Attachments/Pasted%20image%2020211014194311.png)

### Nikto
Command
```
nikto -h http://192.168.143.56:8295 -o enum/nikto.txt
```

Output
```
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3268: /lib/: Directory indexing found.
+ OSVDB-3092: /lib/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7917 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2021-10-14 19:54:42 (GMT-5) (328 seconds)
---------------------------------------------------------------------------
```

### GoBuster
Command
```
gobuster dir -u http://192.168.143.56:8295 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster.txt -f
```

Output
```
===============================================================
/img/                 (Status: 200) [Size: 2987]
/icons/               (Status: 403) [Size: 281] 
/css/                 (Status: 200) [Size: 1141]
/lib/                 (Status: 200) [Size: 2517]
/js/                  (Status: 200) [Size: 932] 
/contactform/         (Status: 200) [Size: 1162]
/server-status/       (Status: 403) [Size: 281] 
                                                
===============================================================
```

---

# Vulnerabilities


---

# Privilege Escalation


---

# Loot
## User
Command
```
ifconfig;id;hostname;cat local.txt
```
>

## Root/Admin
Command
```
ifconfig;id;hostname;cat proof.txt
```
>