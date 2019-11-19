import sys
import struct
import getopt
import socket
import hashlib
from datetime import datetime

FILE_BUFFER_SIZE = 524288

def usage():
    print('Usage: bigfile_server.py <SERVER_PORT>')
    print('SERVER_PORT: Port to which server will listen.')

def random_filename():
    dt_now = datetime.now()
    return dt_now.strftime('%Y%m%d%H%M%S%f')

def readn(sock, count):
    data = b''
    while len(data) < count:
        packet = sock.recv(count - len(data))
        if packet == '':
            return ''
        data += packet
    return data

if __name__ == '__main__':

    #server_port = ''
    #opts, args = getopt.gnu_getopt(sys.argv[1:], 'p:', ['port='])
    #for opt, arg in opts:
    #    if opt in ('-p', '--port'):
    #        server_port = arg

    #if server_port == '':
    #    print('Server port missing.', file=sys.stderr)
    #    usage()
    #    sys.exit(1)

    #if not server_port.isdecimal():
    #    print('Server port contains invalid characters.', file=sys.stderr)
    #    sys.exit(2)

    print('Launching bigfile server.')
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        serv_sock.bind(('10.220.74.146', 1234))
        serv_sock.listen(5)
    except socket.error as e:
        print('Failed to launch server:', e)
        sys.exit(3)
    else:
        print('Server launched, waiting for new connection.')

    try:
        clnt_sock, clnt_addr = serv_sock.accept()
    except socket.error as e:
        print('Failed to accept new connection:', e)
        sys.exit(3)
    else:
        print('New connection from:', clnt_sock)

    size_buff = readn(clnt_sock, 4)
    if size_buff == '':
        print('Failed to receive file size.', file=sys.stderr)
        clnt_sock.close()
        serv_sock.close()
        sys.exit(3)

    size_unpacked = struct.unpack('!I', size_buff)
    file_size = size_unpacked[0]
    print('Will receive file of size', file_size, 'bytes.')

    hash_algo = hashlib.sha256()

    filename = random_filename()
    try:
        with open(filename, 'wb') as file_handle:
            while file_size > 0:
                buffer = clnt_sock.recv(FILE_BUFFER_SIZE)
                print(len(buffer), 'bytes received.')
                if buffer == '':
                    print('End of transmission.')
                    break
                hash_algo.update(buffer)
                file_handle.write(buffer)
                file_size -= len(buffer)
            if file_size > 0:
                print('Failed to receive file,', file_size, 'more bytes to go.')
    except socket.error as e:
        print('Failed to receive data:', e, file=sys.stderr)
        clnt_sock.close()
        serv_sock.close()
        sys.exit(3)
    except IOError as e:
        print('Failed to write file:', e, file=sys.stderr)
        clnt_sock.close()
        serv_sock.close()
        sys.exit(3)
    else:
        print('File transmission completed.')

    clnt_sock.shutdown(socket.SHUT_RD)
    clnt_sock.close()
    serv_sock.close()
    print('Server shutdown.')
    print('SHA256 digest:', hash_algo.hexdigest())

    sys.exit(0)