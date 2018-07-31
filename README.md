This is a heavily modified version of nps_payload, primarily done to make the script platform and version independent (>=Python 2.7) and to eliminate external dependencies (i.e. pexpect and netifaces).


Modifications by Forrest.
Originally written by Larry Spohn (@Spoonman1091)
With payloads written by Ben Mauch (@Ben0xA) aka dirty_ben

-------------------------------------------------------------------------------------------

Origianl Credits:
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

-------------------------------------------------------------------------------------------
v1.04
  Eliminated dependencies, platform specific operations, and specific Python requirements. Reworked output formatting, colors, file management, msfv payload generation, error handling, and a few Pythonic things.

v1.03
  Forked over version 1.03 on 2018-07-31.
  
-------------------------------------------------------------------------------------------
Requirements:
-------------------------------------------------------------------------------------------

Python 2.7 or greater.

-------------------------------------------------------------------------------------------

Setting up samba shares:
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
