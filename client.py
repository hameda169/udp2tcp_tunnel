import socket
import threading
import time

from util import info

localIP = "127.0.0.1"
localPort = 20001

serverIP = "127.0.0.1"
serverPort = 35493

bufferSize = 1500

UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
TCPClientSocket = None

TCPClientLock = threading.RLock()


def create_connect_tcp_socket() -> socket.socket:
    while True:
        info('Creating new socket')
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            info(f'Connecting to {serverIP}:{serverPort}')
            new_socket.connect((serverIP, serverPort))
        except ConnectionRefusedError:
            time.sleep(1)
            continue
        info(f'Connected to {serverIP}:{serverPort}')
        return new_socket


def handle_udp_packet(message, address):
    global TCPClientSocket
    tcp_client_socket_is_not_valid = False
    if not TCPClientSocket:
        info('TCPClientSocket is None')
        tcp_client_socket_is_not_valid = True
    try:
        with TCPClientLock:
            info(f'Sending data of {address} to {serverIP}:{serverPort}')
            TCPClientSocket.sendall(message)
            tcp_response = TCPClientSocket.recv(bufferSize)
        if tcp_response == b'':
            info('Tcp response is empty')
            tcp_client_socket_is_not_valid = True
        else:
            info(f'Sending response of {address}')
            UDPServerSocket.sendto(tcp_response, address)
    except (BrokenPipeError, ConnectionResetError):
        info('Socket Error')
        tcp_client_socket_is_not_valid = True

    if tcp_client_socket_is_not_valid:
        info('TCP Socket is not valid')
        with TCPClientLock:
            TCPClientSocket = create_connect_tcp_socket()
        handle_udp_packet(message, address)


def main():
    global TCPClientSocket
    info('Started')
    TCPClientSocket = create_connect_tcp_socket()
    info(f'TCP connected to {serverIP}:{serverPort}')
    UDPServerSocket.bind((localIP, localPort))
    info(f'Listening on {localIP}:{localPort}')

    while True:
        (message, address) = UDPServerSocket.recvfrom(bufferSize)

        info(f'UDP packet received from {address}')
        handle_udp_packet(message, address)


main()
