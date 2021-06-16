import os, subprocess
import sys
from base64 import b64encode
import crypt

#checking whether program is running as a root or not.
if os.getuid()!=0:
	print("Please, run as root.")			
	sys.exit()

print("Options:")
print("1: new user")
print("2: login")
print("3: update user")
print("4: delete")
option=input("Enter request number: ")
requestOpt=""
uname=""

if option=="1":
	requestOpt="new"
	uname=input("Enter Username you want to add: ")
elif option=="2":
	requestOpt="exist"
	uname=input("Enter your username: ")
elif option=="3":
	requestOpt="update"
	uname=input("Enter your username you want to update: ")
elif option=="4":
	requestOpt="delete"
	uname=input("Enter the username you want to delete: ")


with open('/etc/shadow','r') as fp:		 # Opening shadow file in read mode
	arr=[]
	for line in fp:						 # Enumerating through all the enteries in shadow file
		temp=line.split(':')
		if temp[0]==uname and requestOpt=="new":				  # checking whether entered username exist or not
			print ("FAILURE: user " + uname + " already exists")
			sys.exit()

passwd=input("Enter Password for the user: ")
re_passwd=input("Re-enter Password for the user: ")

# just making sure you know what you are entering in password
if passwd!=re_passwd:
	print("Password do not match")
	exit()

rand1=os.urandom(6)
salt=str(b64encode(rand1).decode('utf-8'))  # generating salt, eight charachters long
hardenedpw=passwd
if requestOpt=="new":
	salt=input("Enter your salt: ")
	initial=input("Enter your initial token: ")
	hardenedpw=passwd+initial
elif requestOpt=="exist":
	currentToken=input("Enter your current token: ")
	nextToken=input("Enter your next token: ")
	userflag=0
	hardenedpw=passwd+currentToken
	with open('/etc/shadow','r+') as f:	
		fp = f.readlines()
		f.seek(0)
		for line in fp:  #Enumerating through all the enteries in shadow file
			temp2=line.split(':')
			if temp2[0]==uname:						  #checking whether entered username exist or not
				userflag=1
				salt_and_pass=(temp2[1].split('$'))	  #retrieving salt against the user
				usersalt=salt_and_pass[2]
				result=crypt.crypt(hardenedpw,'$6$'+usersalt)
				if result!=temp2[1]: 
					print ("FAILURE: either passwd or token incorrect")
					exit()
			else:
				f.write(line)
		f.truncate()
	if userflag==0:
		print("FAILURE: user " + uname + " does not exist")
		exit()
	with open('/etc/passwd', 'r+') as f:
		fp = f.readlines()
		f.seek(0)
		for line in fp:
			temp2=line.split(':')
			if temp2[0]!=uname:
				f.write(line)
		f.truncate()
	hardenedpw=passwd+nextToken
elif requestOpt=="update":
	newpasswd=input("Enter your new password: ")
	newsalt=input("Enter your new salt: ")
	currentToken=input("Enter your current token: ")
	nextToken=input("Enter your next token: ")
	userflag=0
	hardenedpw=passwd+currentToken
	with open('/etc/shadow','r+') as f:	
		fp = f.readlines()
		f.seek(0)
		for line in fp:								 
			temp2=line.split(':')
			if temp2[0]==uname:						  
				userflag=1
				salt_and_pass=(temp2[1].split('$'))	  
				usersalt=salt_and_pass[2]
				result=crypt.crypt(hardenedpw,'$6$'+usersalt)   
				if result!=temp2[1]:					 
					print("FAILURE: either passwd or token incorrect")
					exit()
			else:
				f.write(line)
		f.truncate()
		
	if userflag==0:
		print("FAILURE: user " + uname + " does not exist")
		exit()
	with open('/etc/passwd', 'r+') as f:
		fp = f.readlines()
		f.seek(0)
		for line in fp:
			temp2=line.split(':')
			if temp2[0]!=uname:
				f.write(line)
		f.truncate()
	hardenedpw=newpasswd+nextToken
	salt=newsalt
elif requestOpt=="delete":
	currentToken = input("Enter your current token: ")
	userflag=0
	hardenedpw=passwd+currentToken
	with open('/etc/shadow','r+') as f:	
		fp = f.readlines()
		f.seek(0)
		for line in fp:								 
			temp2=line.split(':')
			if temp2[0]==uname:						  
				userflag=1
				salt_and_pass=(temp2[1].split('$'))	  
				usersalt=salt_and_pass[2]
				result=crypt.crypt(hardenedpw,'$6$'+usersalt)   
				if result!=temp2[1]:					 
					print("FAILURE: either passwd or token incorrect")
					exit()
			else:
				f.write(line)
		f.truncate()
		
	if userflag==0:
		print("FAILURE: user " + uname + " does not exist")
		exit()

if requestOpt=="new" or requestOpt=="exist" or requestOpt=="update":	
	hash=crypt.crypt(hardenedpw,'$6$'+salt)		 # generating hash
	line=uname+':'+hash+":17710:0:99999:7:::"
	file1=open("/etc/shadow","a+")			  # Opening shadow file in append+ mode
	file1.write(line+'\n')				# Making hash entry in the shadow file
	try:
		os.mkdir("/home/"+uname)				# Making home file for the user
	except:
		print("Directory: /home/"+uname+" already exist")
	file2=open("/etc/passwd","a+")			# Opening passwd file in append+ mode

	count=1000				

	with open('/etc/passwd','r') as f:		  # Opening passwd file in read mode
		arr1=[]
		for line in f:
			temp1=line.split(':')
			# checking number of existing UID
			while (int(temp1[3])>=count and int(temp1[3])<65534):
				count=int(temp1[3])+1		   # assigning new uid = 1000+number of UIDs +1

	if requestOpt=="new":
		print("SUCCESS: " + uname + " created")
	elif requestOpt=="exist":
		print("SUCCESS: Login Successful")
	elif requestOpt=="update":
		print("SUCCESS: user " + uname + " updated")

	count=str(count)	
	str1=uname+':x:'+count+':'+count+':,,,:/home/'+uname+':/bin/bash' 
	file2.write(str1)						   # creating entry in passwd file for new user
	file2.write('\n')
	file2.close()
	file1.close()
elif requestOpt=="delete":
	try:
		os.mkdir("/home/"+uname)
	except:
		os.rmdir("/home/"+uname)
	with open('/etc/passwd','r+') as f: 
		fp = f.readlines()
		f.seek(0)   
		for line in fp:								 
			temp2=line.split(':')
			if temp2[0]!=uname:					  
				f.write(line)
		f.truncate()
	print("SUCCESS: user " + uname + " Deleted")

	
