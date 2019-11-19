import socket
import sys

file_name = 'C:\\Users\\barrettj4\\Documents\\GitHub\\COMP2100FinalProject\\James\\testSendfile\\10202111_1600x1200.jpg'
print('Trying to connect...')
s = socket.socket()
s.connect(('10.220.66.144', 1234))

print('Connected. Wating for command.')
while True:
    cmd = s.recv(32).decode()

    if cmd == 'getfilename':
        print('"getfilename" command received.')
        s.sendall(file_name)

    if cmd == 'getfile':
        print('"getfile" command received. Going to send file.')
        with open(file_name, 'rb') as f:
            data = f.read()
        s.sendall('%16d' % len(data))
        s.sendall(data)
        print('File transmission done.')

    if cmd == 'end':
        print('"end" command received. Teminate.')
        break