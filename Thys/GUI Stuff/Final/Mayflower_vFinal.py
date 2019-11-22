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
from datetime import datetime
import socket
from multiprocessing import Process, Queue
import time
import threading
import tkinter
from tkinter import *
import pickle

def popupmsg(msg):
    popup = tkinter.Tk()
    popup.wm_title("!")
    label = tkinter.Label(popup, text=msg)
    label.pack(side="top", fill="x", pady=10)
    B1 = tkinter.Button(popup, text="Okay", command = popup.destroy)
    B1.pack()
    popup.mainloop()


def add_peer_manually():
    global custom_peer_e
    global peer_ip
    custom_peer = custom_peer_e.get()
    add_line_to_output("Connecting to %s" % custom_peer)
    s = socket.socket()
    try:
        s.connect((custom_peer, 1234))
        s.send(b'00')
        add_line_to_output("Connection open to %s on port 1234" % custom_peer)
        peer_list.insert(tkinter.END, custom_peer)
        #peer_ip.set("Peer IP: %s " % custom_peer)
        s.close()
    except socket.error as e:
        add_line_to_output("Connection to %s on port 1234 failed: %s" % (custom_peer, e))

def select_peer():
    if peer_list.curselection():
        selected_peer_ip = peer_list.get(peer_list.curselection())
        peer_ip.set("Peer IP: %s " % selected_peer_ip)
        add_line_to_output("Selected peer: " + str(selected_peer_ip))
        add_line_to_output(peer_ip.get()[9:])
    else:
        add_line_to_output("No peer IP selected or not available")

def readn(sock, count):
    data = b''
    while len(data) < count:
        packet = sock.recv(count - len(data))
        if packet == '':
            return ''
        data += packet
    return data

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

def check_subnet_for_peers(port=1234, timeout=2.0):
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
        #add_line_to_output("Checking ip: " + str(ip))
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

    peer_list.delete(0, END)
    #return found_ips
    if not found_ips:
        peer_list.insert(tkinter.END,"No peers found")
        add_line_to_output("No peers found with network scan")

    peer_list.insert(tkinter.END, found_ips)
    print(found_ips)

def clear_output():
    output_list.delete(0, END)

def add_line_to_output(msg):
    t = datetime.now().strftime('%H:%M:%S')
    output_list.insert(tkinter.END, t+": "+msg)
    output_list.see(END)
    output_list.update_idletasks()

def select_file():
    file_name = askopenfilename()
    #tkinter.Label(window, text=file).grid(row=1, column=1)
    file_name_to_send.set(file_name)
    add_line_to_output("Selected file: %s as file to send" % file_name)
    return file_name
    #file_label.pack()


def scan_dir_for_files():
    basepath = askdirectory()
    #global output_label
    myfiles_list.delete(0, END)
    with os.scandir(basepath) as entries:
        for file in entries:
            if file.is_file():
                myfiles_list.insert(tkinter.END,file.name)
                #output_label.set("Output | Path: %s" % basepath)
                folder_label.set(basepath)
                #ol.update_idletasks()
                add_line_to_output("Added file: '%s' to my file list" %file.name)
    return basepath


def ask_peer_file_list():
    server_addr, server_port = peer_ip.get()[9:-1], '1234'
    add_line_to_output('Connecting to peer.')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(server_addr)
    try:
        conn.connect((server_addr, int(server_port)))
    except socket.error as e:
        add_line_to_output('Failed to connect to peer: {0}'.format(e))

    else:
        add_line_to_output('Connection established for asking.')

    ask = "List:"
    ask = pickle.dumps(ask)
    print(ask)
    conn.sendall(ask)
    peerfiles_list.delete(0, END)
    add_line_to_output("Asking peer file list")

    peer_file_list_recv = conn.recv(FILE_BUFFER_SIZE)
    print("first recv: %s" % peer_file_list_recv)
    print("First recv type: %s" % type(peer_file_list_recv))
    peer_file_list_recv = pickle.loads(peer_file_list_recv)
    print("Second recv: %s " % peer_file_list_recv)
    insert_peer_files(peer_file_list_recv)


def send_myfile_list():
    server_addr, server_port = peer_ip.get()[9:-1], '1234'
    add_line_to_output('Connecting to peer.')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(server_addr)
    try:
        conn.connect((server_addr, int(server_port)))
    except socket.error as e:
        add_line_to_output('Failed to connect to peer: {0}'.format(e))

    else:
        add_line_to_output('Connection established.')

    l = myfiles_list.get(0, END)
    l = list(l)
    print(l)
    l_bytes = pickle.dumps(l)
    print(l_bytes)
    print(type(l_bytes))
    conn.sendall(l_bytes)
    add_line_to_output('Sending my file list to peer.')


def send_file_to_peer():
    global source_file_name
    source_file = source_file_name.get()
    server_addr, server_port = peer_ip.get()[9:-1], '1234'
    file_size = os.path.getsize(source_file)
    add_line_to_output('Sending file {0} to {1}:{2}'.format(source_file, server_addr, server_port))
    add_line_to_output('Source file size: {0} bytes.'.format(file_size))

    add_line_to_output('Connecting to peer.')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((server_addr, int(server_port)))
    except socket.error as e:
        add_line_to_output('Failed to connect to server: {0}'.format(e))

    else:
        add_line_to_output('Connection established.')

    source_file_bytes = "File:{0}".format(source_file).encode()
    source_file_bytes = "File:{0}".format(source_file)

    source_file_pickle = pickle.dumps(source_file_bytes)
    add_line_to_output(str(source_file_bytes))
    print(source_file_pickle)
    conn.sendall(source_file_pickle)

    add_line_to_output('Sending file size to peer.')
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
    except IOError as er:
        add_line_to_output('Failed to open source file {0} : {1} {2}'.format(source_file, er, sys.stderr))

    conn.shutdown(socket.SHUT_WR)
    conn.close()
    add_line_to_output('File sent, connection closed.')
    add_line_to_output('SHA256 digest: {0}'.format(hash_algo.hexdigest()))


def print_file_list():
    l = myfiles_list.get(0, END)
    l = list(l)
    n = 0
    for i in l:
        n = n + 1
        print(n, i)
        peer_list.insert(n, i)


def insert_peer_files(peer_files):
    n = 0
    for i in peer_files:
        print(n, i)
        peerfiles_list.insert(n, i)
        n = n + 1


def select_file_in_list():
    if myfiles_list.index("end") == 0:
        add_line_to_output("No file(s) available")
    elif myfiles_list.curselection():
        list_file = myfiles_list.get(myfiles_list.curselection())
        file_name_to_send.set(str(output_label.get()[15:])+"/"+list_file)
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
        serv_sock.listen(1)
    except socket.error as e:
        print('Failed to launch server:', e)
        add_line_to_output("Failed to launch server: %s" % e)
        serv_sock.close()
        #sys.exit(3)
    else:
        print('Server launched, waiting for new connection.')
        add_line_to_output("Server launched, waiting for new connection.")

    try:
        clnt_sock, clnt_addr = serv_sock.accept()
    except socket.error as e:
        print('Failed to accept new connection:', e)
        add_line_to_output('Failed to accept new connection: %s' % e)
        sys.exit(3)
    else:
        print('New connection from:', clnt_sock)
        add_line_to_output('New connection from: %s on port: %s' % clnt_addr)

    try:
        file_name_recv = clnt_sock.recv(FILE_BUFFER_SIZE)
        print(file_name_recv)
        try:
            file_name_recv = pickle.loads(file_name_recv)
            print(file_name_recv)
        except:
            add_line_to_output("Peer connected manually or with network scan")
        if file_name_recv[:5] == "File:":
            size_buff = readn(clnt_sock, 4)
            if size_buff == '':
                print('Failed to receive file size.', file=sys.stderr)
                add_line_to_output('Failed to receive file size. %s' % sys.stderr)
                clnt_sock.close()
                serv_sock.close()
                sys.exit(3)

            size_unpacked = struct.unpack('!I', size_buff)
            file_size = size_unpacked[0]
            print('Will receive file of size', file_size, 'bytes.')
            add_line_to_output('Will receive file of size %s bytes.' % file_size)

            hash_algo = hashlib.sha256()
            filename_full = file_name_recv.split('/')
            filename = filename_full[-1]
            add_line_to_output("File to receive: %s " % filename)

            try:
                with open(filename, 'wb') as file_handle:
                    while file_size > 0:
                        buffer = clnt_sock.recv(FILE_BUFFER_SIZE)
                        print(len(buffer), 'bytes received.')
                        if buffer == '':
                            print('End of transmission.')
                            add_line_to_output('End of transmission.')
                            break
                        hash_algo.update(buffer)
                        file_handle.write(buffer)
                        file_size -= len(buffer)
                    if file_size > 0:
                        print('Failed to receive file,', file_size, 'more bytes to go.')
                        add_line_to_output('Failed to receive file, %s more bytes to go.' % file_size)
            except socket.error as e:
                print('Failed to receive data:', e, file=sys.stderr)
                add_line_to_output('Failed to receive data: {0} {1}'.format(e, sys.stderr))
                clnt_sock.close()
                serv_sock.close()
                #sys.exit(3)
            except IOError as e:
                print('Failed to write file:', e, file=sys.stderr)
                add_line_to_output('Failed to write data: {0} {1}'.format(e, sys.stderr))
                clnt_sock.close()
                serv_sock.close()
                #sys.exit(3)
            else:
                print('File transmission completed.')
                add_line_to_output('File transmission completed.')

            clnt_sock.shutdown(socket.SHUT_RD)
            clnt_sock.close()
            serv_sock.close()
            print('SHA256 digest:', hash_algo.hexdigest())
            add_line_to_output('SHA256 digest: %s ' % hash_algo.hexdigest())
            print('Server shutdown.')
            add_line_to_output('Server shutdown.')
        elif file_name_recv[:5] == "List:":
            list_to_send = myfiles_list.get(0, END)
            list_to_send = list(list_to_send)
            print("Sending file list: %s" % list_to_send)
            list_to_send_pickle = pickle.dumps(list_to_send)
            print("Pickle: %s" % list_to_send_pickle)
            print("Pickle type: %s" % type(list_to_send_pickle))
            clnt_sock.sendall(list_to_send_pickle)
        elif isinstance(file_name_recv, list):
            print(file_name_recv)
            insert_peer_files(file_name_recv)


    except socket.error as e:
        print("Failed to receive:", e)
        add_line_to_output("Failed to receive: %s" % e)
        clnt_sock.close()
    else:
        print("Client not sending file")
        add_line_to_output("Client not sending file, restarting file server")
        serv_sock.close()
        clnt_sock.close()
        file_server()


def start_server():
    server_thread = threading.Thread(target=file_server)
    server_thread.daemon = True
    server_thread.start()


if __name__ == '__main__':

    FILE_BUFFER_SIZE = 524288

    window = tkinter.Tk()
    window.title("The P2P Mayflower vFinal")
    window.geometry("940x620")
    #window.resizable(0, 0)

    menubar = Menu(window)
    servermenu = Menu(menubar, tearoff=0)
    servermenu.add_command(label="Start server", command=start_server)
    servermenu.add_command(label="(Re)Start server", command=start_server)
    servermenu.add_separator()
    servermenu.add_command(label="Quit Mayflower", command=window.quit)
    menubar.add_cascade(label="Server", menu=servermenu)

    helpmenu = Menu(menubar, tearoff=0)
    helpmenu.add_command(label="General help", command=lambda: popupmsg("Here comes basic help instructions"))
    menubar.add_cascade(label="Help", menu=helpmenu)

    window.config(menu=menubar)

    entryText = tkinter.StringVar()  # is this used?

    # Row 0


    # Row 10
    tkinter.Label(window, text=" ").grid(row=10, column=41)  # white space between lists
    tkinter.Label(window, text=" ").grid(row=10, column=70)  # white space between lists
    tkinter.Label(window, text="File:").grid(row=10, column=10, sticky="W")
    file_name_to_send = tkinter.StringVar()
    source_file_name = tkinter.Entry(window, textvariable=file_name_to_send, width=100)
    source_file_name.grid(row=10, column=20, columnspan=30, sticky="W")
    tkinter.Button(window, text="Browse file", command=select_file).grid(row=10, column=50, sticky="EW")

    tkinter.Label(window, text="IP:").grid(row=10, column=80, sticky="W")
    custom_peer = tkinter.StringVar()
    custom_peer_e = tkinter.Entry(window, textvariable=custom_peer, width=15)
    custom_peer_e.grid(row=10, column=90, sticky="E")

    # Row 20
    tkinter.Label(window, text="Folder:").grid(row=20, column=10, sticky="W", pady=5)
    tkinter.Button(window, text="Browse folder", command=scan_dir_for_files).grid(row=20, column=50, ipadx=1, sticky="W")

    folder_label = tkinter.StringVar()
    folder_label.set("file_path")
    tkinter.Label(window, textvariable=folder_label).grid(row=20, column=20, sticky="W")
    tkinter.Button(window, text="Add peer manually", command=add_peer_manually).grid(row=20, column=80, columnspan=11, sticky="EW")

    # Row 30
    tkinter.Label(window, text="My file list:").grid(row=30, column=10, columnspan=11, sticky="W")
    tkinter.Label(window, text="Peer file list:").grid(row=30, column=45, sticky="W")

    peer_ip = tkinter.StringVar()
    peer_ip.set("Peer IP:")
    tkinter.Label(window, textvariable=peer_ip).grid(row=30, column=50, sticky="E")
    tkinter.Label(window, text="Peer list:").grid(row=30, column=80, columnspan=11, sticky="W")
    tkinter.Button(window, text="Scan", command=check_subnet_for_peers).grid(row=30, column=90, sticky="E")

    # Row 40
    myfiles_list = tkinter.Listbox(window, height=15, width=60)
    myfiles_list.grid(row=40, column=10, columnspan=40, sticky="W")

    peerfiles_list = tkinter.Listbox(window, height=15, width=60)
    peerfiles_list.grid(row=40, column=45, columnspan=11, sticky="W")

    peer_list = tkinter.Listbox(window)
    peer_list.grid(row=40, column=80, columnspan=11, sticky="NSEW")

    # Row 50
    tkinter.Button(window, text="Select file in my file list", command=select_file_in_list).grid(row=50, column=10, columnspan=11, sticky="W")
    tkinter.Button(window, text="Send file!", command=send_file_to_peer).grid(row=50, column=44, sticky="W")
    """   

    local_ip = tkinter.StringVar()
    ip_e = tkinter.Entry(window, textvariable=local_ip, width=35)
    ip_e.grid(row=0, column=1, sticky="E")
    #tkinter.Entry(window, width=40).grid(row=0, column=1, sticky="E")
    # Row 1
    tkinter.Button(window, text="Select peer", command=select_peer).grid(row=1, column=3, sticky="E")

    # Row 4
    output_label = tkinter.StringVar()
    output_label.set("Output | Path:")
    tkinter.Label(window, textvariable=output_label).grid(row=4, column=0, columnspan=6, sticky="W")

    # Row 5, yscrollcommand=yscrollbar.set
    yscrollbar = tkinter.Scrollbar(window)
    xscrollbar = tkinter.Scrollbar(window, orient=HORIZONTAL)
    output_list = tkinter.Listbox(window, height=15, width=123)
    output_list.grid(row=5, column=0, columnspan=5, sticky="W")

    # Row 6
    #tkinter.Button(window, text="Print output to terminal", command=get_list_item).grid(row=6, column=0)
    #tkinter.Button(window, text="Print file list", command=print_file_list).grid(row=6, column=0)
    tkinter.Button(window, text="Send file list", command=send_myfile_list).grid(row=6, column=0, sticky='w')
    tkinter.Button(window, text="ASk", command=ask_peer_file_list).grid(row=6, column=0, sticky='e')
    tkinter.Button(window, text="Clear output", command=clear_output).grid(row=6, column=1)
    
    tkinter.Button(window, text="(Re)start Server", command=start_server).grid(row=6, column=6, sticky="E")
    """
    window.mainloop()
