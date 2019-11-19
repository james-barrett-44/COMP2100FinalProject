import os
from tkinter.filedialog import askdirectory,askopenfilename
from threading import Thread
import threading
import tkinter
from tkinter import *
import os
import sys
import struct
import getopt
import socket
import hashlib
import socket
from datetime import datetime
from multiprocessing import Process, Queue
import time


def add_peer_manually():
    global custom_peer_e
    custom_peer = custom_peer_e.get()
    add_line_to_output("Connecting to %s" % custom_peer)
    s = socket.socket()
    try:
        s.connect((custom_peer, 1234))
        add_line_to_output("Connection open to %s on port 1234" % custom_peer)
        output_list.insert(tkinter.END, custom_peer)
        peer_list.insert(tkinter.END, custom_peer)
        peer_ip.set("Peer IP: s% " % custom_peer)

    except socket.error as e:
        add_line_to_output("Connection to %s on port 1234 failed: %s" % (custom_peer, e))

def check_peer(address, port, queue):
    """
    Check an IP and port for it to be open, store result in queue.
    Based on https://stackoverflow.com/a/32382603
    """
    # Create a TCP socket
    s = socket.socket()
    try:
        s.connect((address, port))
        # print("Connection open to %s on port %s" % (address, port))
        queue.put((True, address, port))
    except socket.error as e:
        # print("Connection to %s on port %s failed: %s" % (address, port, e))
        queue.put((False, address, port))

def get_ip():
    """https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib?rq=1"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
        local_ip.set(IP)
        print(IP)
        add_line_to_output("Own IP address: %s" % IP)
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def check_subnet_for_peers(port=1234, timeout=3.0):
    """https://gist.github.com/awesomebytes/8d5e4ed3b564afa6d3294b2a559e68b7"""
    own_ip = get_ip()
    ip_split = own_ip.split('.')
    subnet = ip_split[:-1]
    subnetstr = '.'.join(subnet)
    add_line_to_output("Start scanning network for peers with subnetmask: %s.0/24" % subnetstr)
    """hardcode subnet range to scan"""
    #subnetstr = '192.168.56'

    q = Queue()
    processes = []
    for i in range(1, 255):
        ip = subnetstr + '.' + str(i)
        #print("Checking ip: " + str(ip))
        #add_line_to_output(str(ip))
        p = Process(target=check_peer, args=[ip, port, q])
        processes.append(p)
        p.start()
    # Give a bit of time...
    time.sleep(timeout)

    found_ips = []
    for idx, p in enumerate(processes):
        # If not finished in the timeout, kill the process
        if p.exitcode is None:
            p.terminate()
        else:
            # If finished check if the port was open
            open_ip, address, port = q.get()
            if open_ip:
                found_ips.append(address)

    #  Cleanup processes
    for idx, p in enumerate(processes):
        p.join()

    #return found_ips
    if not found_ips:
        peer_list.insert(tkinter.END,"No peers found")
        add_line_to_output("No peers found")
    peer_list.insert(tkinter.END, found_ips)
    print(found_ips)


def add_line_to_output(msg):
    t = datetime.now().strftime('%H:%M:%S')
    output_list.insert(tkinter.END, t+": "+msg)
    output_list.update_idletasks()

def select_file():
    file_name = askopenfilename()
    #tkinter.Label(window, text=file).grid(row=1, column=1)
    file_name_to_send.set(file_name)
    add_line_to_output("Selected file: %s as file to send" % file_name)
    return file_name
    #file_label.pack()

def scan_dir():
    #global  myfiles_list
    #basepath = askdirectory()
    #for dir in os.listdir(basepath):
       # if os.path.isdir(os.path.join(basepath, dir)):
            #myfiles_list.insert(tkinter.END,"Folder: %s" % dir)
            #myfiles_list.insert(tkinter.END,dir)
            #tkinter.Label(window, text=f"Folder: {dir}").pack()
            #print(f"Directory: {dir}")

    with os.scandir(basepath) as entries:
        for file in entries:
            if file.is_file():
                #tkinter.Label(window, text=f"File: {file.name}").pack()
                myfiles_list.insert(tkinter.END,"File: %s" % file.name)
                #myfiles_list.insert(tkinter.END,file.name)
                #print(f"File: {file.name}")
                #file_list.append(file.name)

def scan_dir_for_files():
    basepath = askdirectory()

    with os.scandir(basepath) as entries:
        for file in entries:
            if file.is_file():
                myfiles_list.insert(tkinter.END,file.name)
                add_line_to_output("Added file: '%s' to my file list" %file.name)


def send_file_to_peer():
    global e
    source_file = e.get()
    server_addr, server_port = '10.220.49.169', '1234'
    file_size = os.path.getsize(source_file)
    add_line_to_output('Sending file {0} to {1}:{2}'.format(source_file, server_addr, server_port))
    add_line_to_output('Source file size: {0} bytes.'.format(file_size))

    add_line_to_output('Connecting to remote server.')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((server_addr, int(server_port)))
    except socket.error as e:
        add_line_to_output('Failed to connect to server: {0}'.format(e))

    else:
        add_line_to_output('Connection established.')

    add_line_to_output('Sending file size to remote server.')
    buffer = b''
    buffer = struct.pack('!I', file_size)
    add_line_to_output('File size packed into binary format: {0}'.format(buffer))

    try:
        conn.sendall(buffer)
    except socket.error as e:
        add_line_to_output('Failed to send file size:{0}'.format(e))

    else:
        add_line_to_output('File size sent.')

    hash_algo = hashlib.sha256()

    add_line_to_output('Start to send file content.')
    try:
        with open(source_file, 'rb') as file_handle:
            buffer = file_handle.read(FILE_BUFFER_SIZE)
            while len(buffer) > 0:
                conn.sendall(buffer)
                hash_algo.update(buffer)
                buffer = file_handle.read(FILE_BUFFER_SIZE)
    except IOError as e:
        add_line_to_output('Failed to open source file {0} : {1} {2}'.format(source_file, e, file=sys.stderr))


    conn.shutdown(socket.SHUT_WR)
    conn.close()
    add_line_to_output('File sent, connection closed.')
    add_line_to_output('SHA256 digest: {0}'.format(hash_algo.hexdigest()))


def get_list_item():
    l = output_list.get(output_list.curselection())
    print(l)

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


def select_file_in_list():
    #global e
    if myfiles_list.index("end") == 0:
        add_line_to_output("No file(s) available")
    elif myfiles_list.curselection():
        list_file = myfiles_list.get(myfiles_list.curselection())
        file_name_to_send.set(list_file)
        add_line_to_output("Selected file: %s as file to send" % list_file)
    else:
        add_line_to_output("No file selected")


def file_server():
    print('Launching bigfile server.')
    add_line_to_output("Launching bigfile server.")
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        serv_sock.bind((get_ip(), 1234))
        #serv_sock.bind((str(ip_e.get()), 1234))
        serv_sock.listen(5)
    except socket.error as e:
        print('Failed to launch server:', e)
        add_line_to_output("Failed")
        sys.exit(3)
    else:
        print('Server launched, waiting for new connection.')
        add_line_to_output("Server launched, waiting for new connection.")

    try:
        clnt_sock, clnt_addr = serv_sock.accept()
    except socket.error as e:
        print('Failed to accept new connection:', e)
        sys.exit(3)
    else:
        print('New connection from:', clnt_sock)



    try:
        file_name_recv = clnt_sock.recv(FILE_BUFFER_SIZE).decode()
        if file_name_recv[:5] == "File:":
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
    except socket.error as e:
        print("Failed to receive:", e)
        clnt_sock.close()
    else:
        print("Client not sending file")


def start_server():
    server_thread = threading.Thread(target=file_server)
    server_thread.daemon = True
    #server_thread.join()
    server_thread.start()

if __name__ == '__main__':

    FILE_BUFFER_SIZE = 524288

    window = tkinter.Tk()
    window.title("The P2P Mayflower with SERVER")
    window.geometry("910x620")

    # Row 0
    entryText = tkinter.StringVar()
    tkinter.Label(window, text="My IP address:").grid(row=0, column=0, sticky="W")
    tkinter.Button(window, text="Get IP", command=get_ip).grid(row=0, column=3, sticky="W")


    custom_peer = tkinter.StringVar()
    custom_peer_e = tkinter.Entry(window, textvariable=custom_peer, width=20)
    custom_peer_e.grid(row=0, column=3, sticky="E")
    tkinter.Button(window, text="Add peer manually", command=add_peer_manually).grid(row=0, column=6, sticky="W")

    local_ip = tkinter.StringVar()
    ip_e = tkinter.Entry(window, textvariable=local_ip, width=35)
    ip_e.grid(row=0, column=1, sticky="E")

    #tkinter.Entry(window, width=40).grid(row=0, column=1, sticky="E")
    tkinter.Label(window, text=" ").grid(row=0, column=2) #white space between lists
    tkinter.Label(window, text=" ").grid(row=0, column=5) #white space between lists

    # Row 1
    tkinter.Label(window, text="File to send:").grid(row=1, column=0, sticky="W")
    file_name_to_send = tkinter.StringVar()
    e = tkinter.Entry(window, textvariable=file_name_to_send, width=35)
    e.grid(row=1, column=1, sticky="E")
    tkinter.Button(window, text="Choose file", command=select_file).grid(row=1, column=3, sticky="W")
    tkinter.Button(window, text="Scan network for peers", command=check_subnet_for_peers).grid(row=1, column=6, sticky="W")

    # Row 2
    tkinter.Label(window, text="My file list:").grid(row=2, column=0, sticky="W")
    tkinter.Button(window, text="Select file", command=select_file_in_list).grid(row=2, column=1, sticky="W")
    tkinter.Button(window, text="Browse folder", command=scan_dir_for_files).grid(row=2, column=1, sticky="E")
    tkinter.Label(window, text="Peer file list:").grid(row=2, column=3, sticky="W")
    peer_ip = tkinter.StringVar()
    peer_ip = "Peer IP:"
    tkinter.Label(window, text=peer_ip).grid(row=2, column=3, sticky="E")
    tkinter.Label(window, text="Peer list:").grid(row=2, column=6, sticky="W")

    # Row 3
    myfiles_list = tkinter.Listbox(window, height=15, width=60)
    myfiles_list.grid(row=3, column=0, columnspan=2, sticky="W")

    peerfiles_list = tkinter.Listbox(window, height=15, width=60)
    peerfiles_list.grid(row=3, column=3, sticky="W")

    peer_list = tkinter.Listbox(window, height=15, width=25)
    peer_list.grid(row=3, column=6, columnspan=2, sticky="W")

    # Row 4
    tkinter.Label(window, text="Output:").grid(row=4, column=0, sticky="W")

    # Row 5, yscrollcommand=yscrollbar.set
    yscrollbar = tkinter.Scrollbar(window)
    xscrollbar = tkinter.Scrollbar(window, orient=HORIZONTAL)
    output_list = tkinter.Listbox(window, height=15, width=123)
    output_list.grid(row=5, column=0, columnspan=5, sticky="W")

    # Row 6
    tkinter.Button(window, text="Send file!", command=send_file_to_peer).grid(row=6, column=3)
    tkinter.Button(window, text="Print output to terminal", command=get_list_item).grid(row=6, column=0)
    tkinter.Button(window, text="Start Server", command=start_server).grid(row=6, column=6, sticky="E")
    window.mainloop()


