import socket

CHUNK_SIZE = 1024

sock = socket.socket()
sock.connect(('10.220.50.84', 12345))
chunk = sock.recv(CHUNK_SIZE)

with open("testpic.jpg", 'wb') as file_handle:
    while chunk:
        chunk = sock.recv(CHUNK_SIZE)
        print(len(chunk), 'bytes received.')
        file_handle.write(chunk)


#while chunk:
#    chunk = sock.recv(CHUNK_SIZE)
#    print(chunk)
#sock.close()

#with open("test.txt", 'wb') as file_handle:
#    file_handle.write(chunk)