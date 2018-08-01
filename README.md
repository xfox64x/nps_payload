Description
-------------------------------------------------------------------------------------------
This is a heavily modified version of nps_payload, primarily done to make the script platform and version independent (>=Python 2.7) and to eliminate external dependencies (i.e. pexpect and netifaces).


Modifications by Forrest.

Originally written by Larry Spohn (@Spoonman1091).

With payloads written by Ben Mauch (@Ben0xA) aka dirty_ben.



Credits
-------------------------------------------------------------------------------------------
https://github.com/Ben0xA/nps
@Ben0xA

Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations
http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html
@subTee

Bypassing Virtualization and Sandbox Technologies
https://www.trustedsec.com/may-2015/bypassing-virtualization-and-sandbox-technologies/
@HackingDave

Sleeping Your Way out of the Sandbox
https://www.sans.org/reading-room/whitepapers/malicious/sleeping-sandbox-35797
Hassan.morad@gmail.com



Version
-------------------------------------------------------------------------------------------
v1.04
  Eliminated dependencies, platform specific operations, and specific Python requirements. Reworked output formatting, colors, file management, msfv payload generation, error handling, and a few Pythonic things.

v1.03
  Forked over version 1.03 on 2018-07-31.



Requirements
-------------------------------------------------------------------------------------------
Python 2.7 or greater (i.e. Python 3).

Metasploit Framework. For Windows, it is assumed that the framework exists at "C:\metasploit-framework". Follow directions below if not the case.


Directions
-------------------------------------------------------------------------------------------
If using Windows, it is assumed that the Metasploit Framework is installed and MSFVenom exists at "C:\metasploit-framework\bin\msfvenom.bat". If using Nix: "/usr/bin/msfvenom" (which should pretty much always be the case). If this is not the case, modify the variable "msfvenom_full_path" (roughly line 38) to point to the location of msfvenom. If this path ends up not pointing to a valid file, subprocess.Popen will be called on "msfvenom", in hopes that a correctly configured environment will know what to do. This will also probably fail because I can't be bothered to check all of the conditions under which Popen runs in an environment with the correct environment variables defined.


Also if using Nix, modify default_interface (roughly line 30) to be the interface you would like to get the default listening IP from (e.g. "eth0"). This isn't necessary because efforts will be made to select the first non-127.0.0.1 address as the default IP, but if you're one of *those* people, you can modify this variable to meet your needs.


Run the script using Python 2.7+/Python 3.


All output file paths should be listed during execution and will be based off of the current working directory.


Original "Setting up samba shares" directions
-------------------------------------------------------------------------------------------
1. `apt-get install samba`
2. `vi/nano/whatever /etc/samba/smb.conf`
3. add the following to the bottom of the file (change as appropriate)

```
[payloads$]
   comment = Dirty Payloads
   path = /opt/shares/payloads
   browsable = yes
   guest ok = yes
   read only = yes
```
4. `service smbd restart`



TODO:
-------------------------------------------------------------------------------------------
