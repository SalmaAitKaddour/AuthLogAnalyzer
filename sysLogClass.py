import re
import pandas as pd
class sysLogClass:
    
    def __init__(self,timestamp=None,hostname=None,program=None,actor_user=None,target_user=None,ip=None,port=None,module=None,tty=None,pwd=None,command=None,pid=None,event_type=None):
        self.timestamp=timestamp
        self.hostname=hostname
        self.program=program
        self.actor_user = actor_user
        self.target_user = target_user
        self.ip = ip
        self.port = port
        self.module =module
        self.tty = tty
        self.pwd = pwd
        self.command = command
        self.pid =pid
        self.event_type = event_type
        
    
    def parse_line(self,x,a):
            self.timestamp =x[0]+"  "+x[2]+" "+x[3]
            print("timestamp is: ",self.timestamp)
            self.hostname=x[4]
            print("hostname : ",self.hostname)
            print(a[0])
            self.program=re.findall("sudo|sshd|su",a[0])
            program1=self.program[0]
            self.program=program1
            print("program is: ",self.program)
            b=re.findall("\d",a[0])
            if b:
                self.pid=int("".join(b))
                print("pid is : ",self.pid)
    

    def sshdParsing(self,line):
            message = re.search(r"sshd(?:\[\d+\])?:(.*)", line).group(1)
            print(message)
            tmp=message
            message=re.split(" ",message)
            print(message)
            if message[1]=="Accepted":
                self.event_type=message[1]+"_"+message[2]
                print("event type : ",self.event_type)
                self.actor_user=message[4]
                self.ip=message[6]
                self.port=re.split(":",message[8])[0]
                print(self.actor_user,self.ip,self.port)
      
            if message[1]=="Connection" or message[1]=="Received":
                self.event_type=message[1]+"_"+message[2]
                print("event type : ",self.event_type)
                self.ip=message[4]
                self.port=re.split(":",message[6])[0]
                print(self.ip,self.port)
            if re.search("pam_unix",message[1]):
                #message=re.split(" ",tmp)
                #print("message is : ",message)
                self.module="pam_unix"
                self.event_type=message[2]+"_"+message[3]
                print("event-type is : ",self.event_type)
                self.target_user=message[6]
                print("target user: ",self.target_user)
    def sudoParsing(self,line):
            message1 = re.search(r"sudo(?:\[\d+\])?:(.*)", line).group(1)
            tmp=message1
            message1=re.split(";",message1)
            print("message is : ",message1)
            if not re.search("pam_unix",message1[0]):
                self.actor_user=re.search(r"\s(.*):",message1[0]).group(1)
                print(self.actor_user.strip())
                self.tty=re.search(r"\b=(.*)",message1[0]).group(1)
                print(self.tty)
                self.pwd=re.search(r"\b=(.*)",message1[1]).group(1)
                print(self.pwd)
                self.target_user=re.search(r"\b=(.*)",message1[2]).group(1)
                print(self.target_user)
                self.command =re.search(r"\b=(.*)",message1[3]).group(1)
                print(self.command)
            else:
                message1=re.split(" ",tmp)
                print(message1)
                self.module="pam_unix"
                self.event_type=message1[2]+"_"+message1[3]
                print("event-type is : ",self.event_type)
                self.target_user=message1[6]
                print("target user: ",self.target_user)
    def suParsing(self,line):
            message2 = re.search(r"su(?:\[\d+\])?:(.*)", line).group(1)
            message2=re.split(" ",message2)
            print(message2)
            if not re.search("pam_unix",message2[1]):
                self.actor_user=message2[4]
                self.target_user=message2[6]
                print(self.actor_user,self.target_user)
            else:
                self.module="pam_unix"
                self.event_type=message2[2]+"_"+message2[3]
                print("event-type is : ",self.event_type)
                self.target_user=message2[6]
                print("target user: ",self.target_user)

           
    
    
