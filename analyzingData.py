import pandas as pd
import streamlit as st
#chargement 
df=pd.read_csv("auth_events.csv")

# Nettoyage simple
df["target_user"]=df["target_user"].astype(str).str.strip()
df["target_user"] = df["target_user"].replace("nan", pd.NA)

# Comptes
sshdCmpt,sudoCmpt,suCmpt=0,0,0
for x in df["program"]:
    if x=="sshd":
        sshdCmpt+=1
    elif x=="sudo":
        sudoCmpt+=1
    elif x=="su":
        suCmpt+=1
    else:
        continue
ipCmpt=df["ip"].notna().sum()

acceptedSsh=0   
for x in df["event_type"]:
    if x=="Accepted_password" or x=="Accepted_publickey":
        acceptedSsh+=1

# Utilisateurs ciblés
target_users = df["target_user"].dropna().value_counts()

# IP suspectes (brute force)
k=df[df["program"]=="sshd"]["ip"].value_counts().loc[lambda x: x>4]

# Heures actives
df["hour"] = df["timestamp"].str.split().str[2].str.split(":").str[0]
heureActive=df["hour"].value_counts().sort_index()

print("nombre de sudo par utilisateur: ",sudoCmpt)
print("nombre de login ssh par utilisateur: ",sshdCmpt)
print("nombre de su par utilisateur: ",suCmpt)
print("nombre de connexions par IP: ",ipCmpt)
print("Nombre de connexions SSH réussies: ",acceptedSsh)
print("IP qui fait beaucoup de connexions SSH (brute force detection): ",k)
print("Utilisateurs les plus ciblés: ",target_users)
print("Heures les plus actives",heureActive)
# ---------------- UI ----------------
st.title("Auth log – Dashboard")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("SSHD", sshdCmpt)
c2.metric("SUDO", sudoCmpt)
c3.metric("SU", suCmpt)
c4.metric("Connexions avec IP", ipCmpt)
c5.metric("SSH acceptées", acceptedSsh)

st.subheader("Heures les plus actives")
st.bar_chart(heureActive)

st.subheader("Utilisateurs les plus ciblés")
st.dataframe(target_users)

st.subheader("IP avec beaucoup de connexions SSH (suspicion brute-force)")
st.dataframe(k)

st.subheader("Répartition des programmes")
st.bar_chart(df["program"].value_counts())

