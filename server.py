import socket
import threading
from util import info

localIP = "127.0.0.1"
localPort = 35493

serverIP = "127.0.0.1"
serverPort = 20002

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
                UDPClientSocket.sendto(data, (serverIP, serverPort))
                udp_data = UDPClientSocket.recvfrom(bufferSize)[0]
                info(f'UDP packet of {connection_address} received from {serverIP}:{serverPort}')

            info(f'Sending response of {connection_address}')
            connection.send(udp_data)


def main():
    info('Started')
    TCPServerSocket.bind((localIP, localPort))
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
