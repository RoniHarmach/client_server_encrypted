import pickle
import socketserver
import socket
import threading

import client_server_constants
from login_response import LoginResponse
from protocol import Protocol
from protocol_codes import ProtocolCodes
from sign_up_response import SignUpResponse


all_to_die = False

def open_server_socket():
    srv_sock = socket.socket()
    srv_sock.bind((client_server_constants.SERVER_IP, client_server_constants.PORT))
    srv_sock.listen(2)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return srv_sock

def handle_client(sock):
    global all_to_die
    finish = False
    while not finish:
        if all_to_die:
            print("will close due to main server issue")
            break
        code, message = Protocol.read_data(sock)
        if code == ProtocolCodes.LOGIN_REQUEST:
            if message.user == "roni" and message.password == "1":

                response = LoginResponse(result=True)
            else:
                response = LoginResponse(result=False, error=("user / password is incorrect"))

            Protocol.send_data(sock, ProtocolCodes.LOGIN_REQUEST, response)
        elif code == ProtocolCodes.SIGN_UP_REQUEST:
            if message.user == "roni":
                response = SignUpResponse(result=True)
            else:
                response = SignUpResponse(result=False, error="User name already taken..")
            Protocol.send_data(sock, ProtocolCodes.SIGN_UP_RESPONSE, response)
    sock.close()
    print("handle_client cloded")



def accept_clients(srv_sock):
    global all_to_die
    threads = []
    i = 1
    try:
        while True:
            print('\nMain thread: before accepting ...')
            cli_sock, addr = srv_sock.accept()  # accepts an incoming connection request from a TCP client.
            t = threading.Thread(target=handle_client, args=(cli_sock,))
            t.start()  # אומרת לתוכנית לפתוח את הטרד ולהריץ את ההנדל קליינט
            i += 1
            threads.append(t)
            if i > 100000000:  # for tests change it to 4
                print('\nMain thread: going down for maintenance')
                break
            ## מוסיפה למערך של הטרדים
    except socket.timeout:
        print("got timeout")
        all_to_die = True
    finally:

        print("waiting  for all clients to close")
        for t in threads:  #
            print("Joining thread " + t.getName())
            # לכל טרד
            t.join()  # עוצר את הטרייד מיין עד ש הטי סוגר את עצמו
        print("All Client threads ended")
        srv_sock.close()


def main():
    global all_to_die
    srv_sock = open_server_socket()
    accept_clients(srv_sock)


if __name__ == "__main__":
    main()
