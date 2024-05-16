import pickle
import socket, sys
from random import random

import client_server_constants
from encryption import Encryption
from protocol_codes import ProtocolCodes
from protocol import Protocol
from login_app2 import LoginApp
from user_login_protocol import UserLoginProtocol
import random

connected = False

def handle_server_messages(server_socket):
    global connected
    while connected:
        code, bdata = Protocol.read_data(server_socket)
        if code == ProtocolCodes.SERVER_DISCONNECT:
            print("Server disconnected")
            server_socket.close()
            break

        if bdata == b'' and code not in [ProtocolCodes.START_GAME, ProtocolCodes.GAME_INIT]:
            print('Seems server disconnected abnormally')
            break
        if code == ProtocolCodes.GAME_RESULTS:
            connected = False


def open_client_socket(ip):
    global connected
    sock = socket.socket()
    port = 6060
    try:
        sock.connect((ip, port))
        print(f'Connect succeeded {ip}:{port}')
        connected = True
        return sock
    except:
        print(f'Error while trying to connect.  Check ip or port -- {ip}:{port}')
        return None


def login_callback():
    print("logged in")


def main(server_ip, port):
    sock = socket.socket()
    sock.connect((server_ip, port))

    user_login_protocol = UserLoginProtocol(sock)
    app = LoginApp(user_login_protocol)
    app.run()
   # app root.mainloop()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1], sys.argv[2])
    else:
        main(client_server_constants.SERVER_IP, client_server_constants.PORT)
        #main('0.0.0.0')