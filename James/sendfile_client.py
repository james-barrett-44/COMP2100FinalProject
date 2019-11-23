import os
import sys
import struct
import getopt
import socket
import hashlib

FILE_BUFFER_SIZE = 524288

def usage():
    print('Usage: bigfile_client.py <ARGUMENTS>')
    print('ARGUMENTS:')
    print('[-f|--file]: Source file to send.')
    print('[-h|--host]: Server address.')
    print('[-p|--port]: Server port number.')

if __name__ == '__main__':

    source_file, server_addr, server_port = '', '', ''
    opts, args = getopt.gnu_getopt(sys.argv[1:], 'f:h:p:', ['file=', 'host=', 'port='])
    for opt, arg in opts:
        if opt in ('-f', '--file'):
            source_file = arg
        elif opt in ('-h', '--host'):
            server_addr = arg
        elif opt in ('-p', '--port'):
            server_port = arg

    if source_file == '':
        print('Source file missing.', file=sys.stderr)
        usage()
        sys.exit(1)
    elif server_addr == '':
        print('Server address missing.', file=sys.stderr)
        usage()
        sys.exit(1)
    elif server_port == '':
        print('Server port number missing.', file=sys.stderr)
        usage()
        sys.exit(1)

    if not os.path.isfile(source_file):
        print('Source file cannot be found.', file=sys.stderr)
        sys.exit(2)
    elif not server_port.isdecimal():
        print('Server port number contains invalid characters.', file=sys.stderr)
        sys.exit(2)

    file_size = os.path.getsize(source_file)
    print('Sending file {0} to {1}:{2}.'.format(source_file, server_addr, server_port))
    print('Source file size:', file_size, 'bytes.')

    print('Connecting to remote server.')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((server_addr, int(server_port)))
    except socket.error as e:
        print('Failed to connect to server:', e)
        sys.exit(3)
    else:
        print('Connection established.')

    print('Sending file size to remote server.')
    buffer = b''
    buffer = struct.pack('!I', file_size)
    #buffer = struct.pack('@I', file_size)
    print('File size packed into binary format:', buffer)

    try:
        conn.sendall(buffer)
    except socket.error as e:
        print('Failed to send file size:', e)
        sys.exit(3)
    else:
        print('File size sent.')

    hash_algo = hashlib.sha256()

    print('Start to send file content.')
    try:
        with open(source_file, 'rb') as file_handle:
            buffer = file_handle.read(FILE_BUFFER_SIZE)
            while len(buffer) > 0:
                conn.sendall(buffer)
                hash_algo.update(buffer)
                buffer = file_handle.read(FILE_BUFFER_SIZE)
    except IOError as e:
        print('Failed to open source file', source_file, ':', e, file=sys.stderr)
        sys.exit(3)

    conn.shutdown(socket.SHUT_WR)
    conn.close()
    print('File sent, connection closed.')
    print('SHA256 digest:', hash_algo.hexdigest())

    sys.exit(0)