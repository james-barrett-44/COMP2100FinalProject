#!/usr/bin/python3

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
    subnetstr = '10.220.67'

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

if __name__ == '__main__':
    port = 1234
    peer_ip_list = check_subnet_for_peers(port)

    print(peer_ip_list)
