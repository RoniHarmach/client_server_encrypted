import pickle
from protocol_codes import ProtocolCodes


class Protocol:

    DELIMITER = '#'

    @staticmethod
    def send_data(sock, code, message):
        serialized_message = pickle.dumps(message)
        content = code.value.encode() + Protocol.DELIMITER.encode() + serialized_message
        bytearray_data = str(len(content)).zfill(8).encode() \
                         + Protocol.DELIMITER.encode() \
                         + content

        index = 0
        while index < len(bytearray_data):
            size = min(1000, len(bytearray_data) - index)
            sock.send(bytearray_data[index:index + size])
            index += size

    @staticmethod
    def split_length_field(byte_data):
        length = int(byte_data[:8].decode())
        byte_data = byte_data[9:]
        return length, byte_data

    def recv_message(sock):
        message = sock.recv(1000)
        if message == b'':
            return message

        message_size = int(message[:8].decode())
        current_size = len(message[9:])
        while current_size < message_size:
            current_message = sock.recv(1000)
            message += current_message
            current_size += len(current_message)

        return message

    @staticmethod
    def read_data(sock):
        data = sock.recv(1000)
        # if data == b'':
        #     return ProtocolCodes.CLIENT_DISCONNECTED, b''
        message_size, message = Protocol.split_length_field(data)
        current_size = len(message)
        while current_size < message_size:
            current_message = sock.recv(1000)
            message += current_message
            current_size += len(current_message)

        code_value = message[:4].decode()
        return ProtocolCodes(code_value), pickle.loads(message[5:])


