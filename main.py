import re
import pandas as pd
from sysLogClass import sysLogClass
Liste=[["timestamp","hostname","program","actor_user","target_user","ip","port","module","tty","pwd","command","pid","event_type"]]
df = pd.DataFrame(columns=Liste[0])

with open(r"C:\Users\21276\Desktop\Formation\sys-log\AuthLog.txt") as f:
    i,sshdCmpt,sudoCmpt,suCmpt=0,0,0,0
    for line in f:
        e=sysLogClass()
        x=re.split(" ",line)
        if len(x)<6:
            continue
        a=re.findall("^sudo.*:$|^sshd.*:$|^su.*:$",x[5])
        if a:
            #line parsing 
            e.parse_line(x,a)
        
            #Parsing des lignes sshd
            if e.program=="sshd":
                sshdCmpt+=1
                e.sshdParsing(line)
    
            #parsing des lignes sudo
            elif e.program=="sudo":
                sudoCmpt+=1
                e.sudoParsing(line)
       
            #parsing des lignes su
            elif e.program=="su":
                suCmpt+=1
                e.suParsing(line)
            else:
                continue
        else:
            continue
        #ajoute de la ligne a la liste
        lineAuth=[e.timestamp,e.hostname,e.program,e.actor_user,e.target_user,e.ip,e.port,e.module,e.tty,e.pwd,e.command,e.pid,e.event_type]
        Liste.append(lineAuth)
        df.loc[len(df)] = lineAuth
        if i==66:
           break
        i+=1


df.to_csv(r"C:\Users\21276\Desktop\Formation\sys-log\auth_events.csv")
print("nombre de sudo par utilisateur: ",sshdCmpt)
print("nombre de login ssh par utilisateur: ",sudoCmpt)
print("nombre de su par utilisateur: ",suCmpt)


