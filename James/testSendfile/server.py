import socket

import socket

server_socket = socket.socket()
server_socket.bind(('10.220.50.84', 12345))
server_socket.listen(5)
while True:
    client_socket, addr = server_socket.accept()
    with open('C:\\Users\\barrettj4\\Documents\\GitHub\\COMP2100FinalProject\\James\\testSendfile\\10202111_1600x1200.jpg', 'rb') as f:
        client_socket.sendfile(f, 0)
    client_socket.close()
