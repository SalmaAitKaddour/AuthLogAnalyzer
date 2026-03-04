import re
ligne1="Feb  5 23:55:19 server sudo:     root : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/tar -x --keep-directory-symlink -f /var/tmp/labsys.tar -C /"
ligne2="Feb  6 00:10:05 server sshd[207]: Accepted password for ubuntu from 172.20.0.2 port 39506 ssh2"
ligne3="Feb  6 00:15:13 server su[313]: Successful su for root by root"
ligne4="Feb  5 23:55:19 server sudo: pam_unix(sudo:session): session opened for user root by (uid=0)"
ligne5="Feb  6 00:10:06 server sshd[207]: pam_unix(sshd:session): session closed for user ubuntu"
ligne6="Feb  6 00:15:13 server su[313]: pam_unix(su:session): session opened for user root by ubuntu(uid=0)"
ligne7="Feb  6 00:10:06 server sshd[216]: Received disconnect from 172.20.0.2 port 39506:11: disconnected by user"
x=re.split(" ",ligne2)
print(x)

timestamp=x[0]+"  "+x[2]+" "+x[3]
print("timestamp is: ",timestamp)

hostname=x[4]
print("hostname : ",hostname)

a=re.findall("^sudo.*:$|^sshd.*:$|^su.*:$",x[5])
#print(a[0])
program=re.findall("sudo|sshd|su",a[0])
print("program is: ",program[0])

b=re.findall("\d",a[0])
if b:
   pid=int("".join(b))
   print("pid is : ",pid)

#Parsing des lignes sshd
if program[0]=="sshd":
   message = re.search(r"sshd(?:\[\d+\])?:(.*)", ligne2).group(1)
   print(message)
   tmp=message
   message=re.split(" ",message)
   print(message)
   if message[1]=="Accepted":
      event_type=message[1]+"_"+message[2]
      print("event type : ",event_type)
      user=message[4]
      ip=message[6]
      port=re.split(":",message[8])[0]
      print(user,ip,port)
      
   if message[1]=="Connection" or message[1]=="Received":
      event_type=message[1]+"_"+message[2]
      print("event type : ",event_type)
      ip=message[4]
      port=champ=re.split(":",message[6])[0]
      print(ip,port)
   if re.search("pam_unix",message[1]):
      #message=re.split(" ",tmp)
      #print("message is : ",message)
      module="pam_unix"
      event_type=message[2]+"_"+message[3]
      print("event-type is : ",event_type)
      target_user=message[6]
      print("target user: ",target_user)
      
   
#parsing des lignes sudo
if program[0]=="sudo":
   
   message1 = re.search(r"sudo(?:\[\d+\])?:(.*)", ligne4).group(1)
   tmp=message1
   message1=re.split(";",message1)
   print("message is : ",message1)
   if not re.search("pam_unix",message1[0]):
      actor_user=re.search(r"\s(.*):",message1[0]).group(1)
      print(actor_user.strip())
      tty=re.search(r"\b=(.*)",message1[0]).group(1)
      print(tty)
      pwd=re.search(r"\b=(.*)",message1[1]).group(1)
      print(pwd)
      target_user=re.search(r"\b=(.*)",message1[2]).group(1)
      print(target_user)
      command =re.search(r"\b=(.*)",message1[3]).group(1)
      print(command)
   else:
      message1=re.split(" ",tmp)
      print(message1)
      module="pam_unix"
      event_type=message1[2]+"_"+message1[3]
      print("event-type is : ",event_type)
      target_user=message1[6]
      print("target user: ",target_user)

#parsing des lignes su
if program[0]=="su":
   message2 = re.search(r"su(?:\[\d+\])?:(.*)", ligne6).group(1)
   message2=re.split(" ",message2)
   print(message2)
   if not re.search("pam_unix",message2[1]):
      actor_user=message2[4]
      target_user=message2[6]
      print(actor_user,target_user)
   else:
      module="pam_unix"
      event_type=message2[2]+"_"+message2[3]
      print("event-type is : ",event_type)
      target_user=message2[6]
      print("target user: ",target_user)

