#Erez Rigevsky, 322214172, Allen Bronshtein, 206228751
import socket, base64, threading,os
from sys import argv
from sender import check_port
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from datetime import datetime

# Global variables
PASSWORD,SALT,IP,PORT,s,f = None,None,'',None,None,None

def load():
    global PASSWORD,SALT,IP,PORT,s,f
    try: PASSWORD, SALT, PORT = argv[1],argv[2],int(argv[3])
    except Exception: exit(1)
    if not check_port(PORT): exit(1)     
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=SALT.encode(),iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(PASSWORD.encode()))
    f = Fernet(key)  
    IP = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.bind((IP,PORT))
    except Exception:
        print('Couldnt bind port ' + str(PORT))
        exit(1)    

def handle_client(client_socket,address):
    while True:
        try:
            cipher = client_socket.recv(4096)
            plain = f.decrypt(cipher).decode('utf-8')
        except Exception: break
        print(f'{plain} {str(datetime.now().time())[0:8]}')

if __name__ == '__main__':
    load()
    s.listen()
    while True:
        print(f'Listening on ({IP}:{PORT})')
        client_socket , address = s.accept()
        thread = threading.Thread(target = handle_client, args = (client_socket,address))
        thread.start()