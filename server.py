import socket
import threading
import sys
import argparse
from util import info

parser = argparse.ArgumentParser()
parser.add_argument('--local', default='127.0.0.1:35493')
parser.add_argument('--server', default='127.0.0.1:20002')

(localIP, localPort) = parser.parse_args(sys.argv[1:]).local.split(':')
(serverIP, serverPort) = parser.parse_args(sys.argv[1:]).server.split(':')


TIMEOUT = 10
bufferSize = 1500

TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

UDPClientLock = threading.RLock()


def handle_tcp_packet(connection: socket.socket, connection_address: str):
    info('Handling new socket')
    with connection:
        while True:
            try:
                connection.settimeout(TIMEOUT)
                data = connection.recv(bufferSize)
            except socket.timeout:
                info(f'Socket timeout for {connection_address}')
                break

            with UDPClientLock:
                info(f'Sending UDP from {connection_address} to {serverIP}:{serverPort}')
                UDPClientSocket.sendto(data, (serverIP, int(serverPort)))
                udp_data = UDPClientSocket.recvfrom(bufferSize)[0]
                info(f'UDP packet of {connection_address} received from {serverIP}:{serverPort}')

            info(f'Sending response of {connection_address}')
            connection.send(udp_data)


def main():
    info('Started')
    TCPServerSocket.bind((localIP, int(localPort)))
    TCPServerSocket.listen()
    info(f'Listening on {localIP}:{localPort}')
    while True:
        try:
            (client_connection, client_address) = TCPServerSocket.accept()
            info(f'Client accepted: {client_address}')
        except KeyboardInterrupt:
            info('Stopped')
            break

        threading.Thread(target=handle_tcp_packet, args=(client_connection, client_address)).start()

    TCPServerSocket.close()


main()
