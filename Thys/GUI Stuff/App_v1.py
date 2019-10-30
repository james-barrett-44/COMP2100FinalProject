import os
from tkinter.filedialog import askdirectory,askopenfilename
from threading import Thread
import tkinter
from tkinter import *
import os
import sys
import struct
import getopt
import socket
import hashlib
import socket
from multiprocessing import Process, Queue
import time

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
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def check_subnet_for_peers(port, timeout=3.0):
    """https://gist.github.com/awesomebytes/8d5e4ed3b564afa6d3294b2a559e68b7"""
    own_ip = get_ip()
    #print("Got own ip: " + str(own_ip))
    ip_split = own_ip.split('.')
    subnet = ip_split[:-1]
    subnetstr = '.'.join(subnet)

    """hardcode subnet range to scan"""
    subnetstr = '192.168.56'

    q = Queue()
    processes = []
    for i in range(1, 255):
        ip = subnetstr + '.' + str(i)
        #print("Checking ip: " + str(ip))
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

    return found_ips


def add_line_to_output(msg):
    output_list.insert(tkinter.END, msg)

def select_file():
    file_name = askopenfilename()
    #tkinter.Label(window, text=file).grid(row=1, column=1)
    file_name_to_send.set(file_name)
    return file_name
    #file_label.pack()

def scan_dir():
    basepath = askdirectory()
    for dir in os.listdir(basepath):
        if os.path.isdir(os.path.join(basepath, dir)):
            tkinter.Label(window, text=f"Folder: {dir}").pack()
            #print(f"Directory: {dir}")

    with os.scandir(basepath) as entries:
        for file in entries:
            if file.is_file():
                tkinter.Label(window, text=f"File: {file.name}").pack()
                #print(f"File: {file.name}")
                #file_list.append(file.name)


def send_file_to_peer():
    global e
    source_file = e.get()
    server_addr, server_port = '192.168.56.1', '3000'
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

FILE_BUFFER_SIZE = 524288

window = tkinter.Tk()
window.title("The P2P Mayflower")
window.geometry("910x620")



# Row 0
entryText = tkinter.StringVar()
tkinter.Label(window, text="My IP address:").grid(row=0, column=0, sticky="W")
tkinter.Entry(window, width=40).grid(row=0, column=1, sticky="E")
tkinter.Label(window, text="  ").grid(row=0, column=2) #white space between lists
tkinter.Label(window, text=" ").grid(row=0, column=5) #white space between lists

# Row 1
tkinter.Label(window, text="File to send:").grid(row=1, column=0, sticky="W")
file_name_to_send = tkinter.StringVar()
e = tkinter.Entry(window, textvariable=file_name_to_send, width=40)
e.grid(row=1, column=1, sticky="E")
tkinter.Button(window, text="Choose file", command=select_file).grid(row=1, column=3, sticky="W")

# Row 2
tkinter.Label(window, text="My file list:").grid(row=2, column=0, sticky="W")
tkinter.Label(window, text="Peer file list:").grid(row=2, column=3, sticky="W")
tkinter.Label(window, text="Peer list:").grid(row=2, column=6, sticky="W")

# Row 3
myfiles_list = tkinter.Listbox(window, height=15, width=60)
myfiles_list.grid(row=3, column=0, columnspan=2)

peerfiles_list = tkinter.Listbox(window, height=15, width=60)
peerfiles_list.grid(row=3, column=3)

peer_list = tkinter.Listbox(window, height=15, width=25)
peer_list.grid(row=3, column=6, columnspan=2)

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
window.mainloop()
