This is a heavily modified version of nps_payload, primarily done to make the script platform and Python version independent (>=Python 2.7) and eliminate external dependencies (i.e. pexpect). 


Modifications by Forrest.
Originally written by Larry Spohn (@Spoonman1091)
With payloads written by Ben Mauch (@Ben0xA) aka dirty_ben
-------------------------------------------------------------------------------------------

Origianl Credits:

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
  Did too many things.

v1.03
  Cleaned up the output of the payload creation to make it easier to read and copy & paste.

v1.02
  Fixed logic in creation of a new msbuild.rc resource script

v1.01
  Added "Custom PS1 Payload" option.

v1.0
  Initial Release

-------------------------------------------------------------------------------------------

Requirements:

>= Python 2.7
-------------------------------------------------------------------------------------------

Setting up samba shares:

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
