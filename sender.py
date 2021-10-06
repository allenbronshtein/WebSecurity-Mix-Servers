#Erez Rigevsky, 322214172, Allen Bronshtein, 206228751
import socket, base64, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sys import argv
from datetime import datetime, timedelta
from time import sleep
from os import path

#global variables
SERVERS,MESSAGES,MSG_Q,s = {},None,None,None #SERVERS = {num:server_data}

class MessageQueue: # Message queue for those whose round is not 0
    def __init__(self):
        self.waiting_q = []

    def add(self,package): # Add new package to queue
        takeout_time = datetime.now() + timedelta(seconds=package.hold_time) 
        size = len(self.waiting_q)
        for i in range(0,size):
            if takeout_time < self.waiting_q[i][0]:
                self.waiting_q.insert(i,(takeout_time, package))
                return
        self.waiting_q.append((takeout_time,package))
    
    def round_send(self): # Round send implementation
        now = datetime.now()
        i = 0
        for item in self.waiting_q:
            time_to_send = item[0]
            if now >= time_to_send:
                p = self.waiting_q[i][1]
                i += 1
                send(p)
            else: break
        for j in range(0,i): self.waiting_q.pop(0)           

    def is_empty(self): # Check if queuee is  empty
        return not self.waiting_q

class Package: #Each package is message to be sent
    def __init__(self,dest_ip,dest_port,c,hold_time):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.cipher = c
        self.hold_time = hold_time

class Server: # Contains information about each server   
    def __init__(self,ip,port,pk):
        self.ip = ip
        self.port = port
        self.pk = pk

def load(): # Loads all data before running
    global SERVERS,MESSAGES,MSG_Q,s
    # ------------ Check given arguments ------------- #
    try: 
        x = argv[1]
        int(x)
    except Exception: 
        print('Invalid argument given')
        exit(1)
    # ------------------------------------------------ #

    # ------------ Get all messages------------------- #
    file_name = 'messages' + x + '.txt'
    f = open(file_name,'r')
    MESSAGES = f.read().split('\n')
    f.close()
    if len(MESSAGES) == 0: # No messages to send
        print('No messages were found')
        exit(1) 
    # ------------------------------------------------ #

    # ------------ Make public keys ---- ------------- #
    i = 1
    pks = []
    while True:
        fname = f'pk{i}.pem'
        if not os.path.isfile(fname):
            break
        f = open('pk1.pem','rb')
        pk_str = f.read()
        f.close()
        try:
            pk = load_pem_public_key(pk_str)
        except Exception: 
            print(f'Couldnt load public key {i}')
            exit(1)
        pks.append(pk)
        i += 1
    # ------------------------------------------------- #

    # ------------ Get servers addresses -------------- #
    f = open('ips.txt','r')
    addresses = f.read().split('\n')
    f.close()
    if len(addresses) != len(pks): # Missing server address
        print('Number of servers and public keys doesnt match')
        exit(1) 
    # ------------------------------------------------ #

    # ------------ Create servers data- -------------- #
    num_of_servers = len(addresses)
    for i in range(0,num_of_servers):
        address = addresses[i].split(' ')
        ip,port = address[0],address[1]
        if not check_ip(ip) or not check_port(port): 
            print('Bad servers ip or port')
            exit(1)
        if ip == '127.0.0.1':
            ip = socket.gethostbyname(socket.gethostname())
        SERVERS[i+1] = Server(ip,int(port),pks[i]) # Dictionary
    # ------------ ----------------------------------- #
    MSG_Q = MessageQueue()
                
def check_path(path): # Checks if path is valid
    path = path.split(',')
    flag = False
    for node in path:
        try: int(node)
        except Exception: flag = True
    return not flag

def check_time(time):# Checks if time for sending is valid 
    try:int(time)
    except Exception: return False
    return True

def check_ip(ip):# Checks if given ip is valid
    ip = ip.split('.')
    if len(ip) != 4: return False
    for num in ip:
        try: n = int(num)
        except Exception: return False
        if n <0 or n > 255: return False
    return True

def check_port(port): # Checks if given port is valid
    try: port = int(port)
    except Exception: return False
    return 0<=port and port<=65535

def get_fernet(pw,_salt): # Generates fernet for message
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=_salt.encode(),iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    return Fernet(key)   

def sformat_msg(ip,port,c): # Creates message in format readable for server
    msg = ''
    ip = ip.split('.')
    for i in ip:
        msg = msg +  "\\x"
        t = hex(int(i))[2:]
        if len(t) == 1: t = '0' + t
        msg += t
    msg =msg +  '\\x'
    t = hex(int(port))[2:]
    while len(t) != 4:
        t = '0' + t
    msg = msg + t[0:2] + '\\x' + t[2:4]
    msg +=str(c)
    return msg

def pk_encrypt(pk,ip,port,c): # Encrypts message according to number of server
    msg = sformat_msg(ip,port,c)
    print(msg)
    c = pk.encrypt(msg.encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))    
    return c

def send(package): # Sends package
    global s
    ip,port,c=package.dest_ip,package.dest_port,package.cipher
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try: 
        s.connect((ip,port))
    except Exception: 
        print(f'Couldnt connect to [{ip},{port}]')
    try:
        s.send(c)
    except Exception: print('Couldnt send data')
    s.close()

def create_package(plain,path,dest_ip,dest_port,time,pw,salt):
    global SERVERS
    f = get_fernet(pw,salt)
    path = path.split(',')
    next_ip, next_port = dest_ip,dest_port
    c = f.encrypt(plain.encode())
    path.reverse()
    for num in path:
        server_num = int(num)
        if server_num not in SERVERS.keys(): continue
        server = SERVERS[server_num]
        pk = server.pk
        c = pk_encrypt(pk,next_ip,next_port,c)
        next_ip,next_port = server.ip,server.port
    return Package(next_ip,next_port,c,time)

if __name__ == '__main__':
    argv.append('1')
    load()
    for message in MESSAGES:
        args = message.split(' ')
        try: plain,path,time,pw,salt,dest_ip,dest_port = args[0],args[1],int(args[2]),args[3],args[4],args[5],int(args[6])
        except Exception: continue
        if not check_path(path) or not check_time(time) or not check_ip(dest_ip) or not check_port(dest_port): continue
        if ip == '127.0.0.1':
            ip = socket.gethostbyname(socket.gethostname())
        package = create_package(plain,path,dest_ip,dest_port,time,pw,salt)
        if time == 0:
            send(package)
        else:
            MSG_Q.add(package)
    while not MSG_Q.is_empty():
        MSG_Q.round_send()
        sleep(60)