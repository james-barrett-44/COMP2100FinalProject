import socket
import os

print('Waiting for client to connect...')
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.bind(('10.220.66.144', 1234))
c.listen(1)
s, a = c.accept()

print('Connected. Going to receive file.')
s.sendall('getfile'.encode())
s#.sendall(b'getfilename')
filename = s.recv(1024).decode()
if '/' in filename:
    dir = os.path.dirname(filename)
    try:
        os.stat(dir)
    except:
        print('Directory does not exist. Creating directory.')
        os.mkdir(dir)
f = open(filename, 'wb')
print('Filename: ' + filename)

while True:
    s.sendall('getfile'.encode())
    size = int(s.recv(16))
    print('Total size: ' + str(size))
    recvd = ''
    while size > len(recvd):
        data = s.recv(1024).decode()
        print(len(data), 'bytes received.')
        if not data:
            break
        recvd += data
        f.write(data)
        #print(len(recvd))
    break
s.sendall('end'.encode())
print('File received.')

s.close()
c.close()
f.close()