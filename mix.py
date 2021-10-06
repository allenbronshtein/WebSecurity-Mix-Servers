# Erez Rigevsky, 322214172, Allen Bronshtein, 206228751
import socket, datetime, random, sys
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

countdown_finished = False


# define the countdown func.
def countdown():
    global countdown_finished
    now = datetime.datetime.now()
    new_now = datetime.datetime.now()
    while (new_now - now).total_seconds() < 60.0:
        new_now = datetime.datetime.now()

    countdown_finished = True
    # print('minute over')
    return


def send_messages(messages):
    length = len(messages)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while length != 0:
        # print('in list')
        index = 0
        if length != 1:
            index = random.randint(0, length-1)
        message = messages[index]
        messages.pop(index)
        length = len(messages)
        ip_b = message[:4]
        ip_to_send = '{}.{}.{}.{}'.format(*bytearray(ip_b))
        message = message[4:]
        port_b = message[:2]
        message = message[2:]
        #if message.decode().startswith('b"') and message.endswith('"'):
        message = message[2:-1]
        # print(message)
        port_to_send = int.from_bytes(port_b, 'big')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip_to_send, port_to_send))
        except Exception:
            print(f'Could not connect to [{ip_to_send},{port_to_send}]')
        try:
            s.send(message)
            # print('sent')
        except Exception:
            print('Could not send data')
    s.close()


if __name__ == '__main__':
    # create private and public key
    try:
        y = sys.argv[1]
        file_name = 'sk' + y + '.pem'
        sky_file = open(file_name, 'r')
        sky_b = sky_file.read().encode()
        private_key = serialization.load_pem_private_key(sky_b, password=None, backend=default_backend())
        public_key = private_key.public_key()
    except Exception:
        exit(1)

    # Create socket
    ips_file = open('ips.txt')
    ips = ips_file.read()
    ips = ips.split('\n')
    port = int(ips[int(y)-1].split(' ')[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', port)
    server_socket.bind(server_address)
    server_socket.listen()
    # print('Listening on port %s ...' % port)

    while True:
        countdown_thread = threading.Thread(target=countdown)
        countdown_thread.start()
        messages_list = []
        server_socket.settimeout(0.1)
        while not countdown_finished:
            # Wait for client connections
            try:
                client_connection, client_address = server_socket.accept()
                client_connection.settimeout(None)
                # Get the client request
                ciphertext = client_connection.recv(4096)
                message = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                message = message.decode('unicode-escape').encode('ISO-8859-1')
                messages_list.append(message)
                client_connection.close()
            except socket.timeout as e:
                pass
            except Exception:
                exit(1)
        countdown_finished = False
        # print("finished")
        copy = messages_list.copy()
        send_messages_thread = threading.Thread(target=send_messages(copy))
        send_messages_thread.start()

    # Close socket
    server_socket.close()
