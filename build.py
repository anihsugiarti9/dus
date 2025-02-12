# -*- coding: utf-8 -*-
"""
 Socks5 Proxy Server with Authentication in Python
"""

import socket
import select
from struct import pack, unpack
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys

# Konfigurasi
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050
USERNAME = "akuganteng"  # Ganti dengan username yang diinginkan
PASSWORD = "akukaya"  # Ganti dengan password yang diinginkan

# Konstanta
VER = b'\x05'
M_NOAUTH = b'\x00'
M_USERPASS = b'\x02'
M_NOTAVAILABLE = b'\xff'
CMD_CONNECT = b'\x01'
ATYP_IPV4 = b'\x01'
ATYP_DOMAINNAME = b'\x03'

class ExitStatus:
    def __init__(self):
        self.exit = False
    def set_status(self, status):
        self.exit = status
    def get_status(self):
        return self.exit

EXIT = ExitStatus()

def error(msg="", err=None):
    if msg:
        traceback.print_exc()
        print(f"{msg} - Code: {err[0]}, Message: {err[1]}")
    else:
        traceback.print_exc()

def authenticate(wrapper):
    """Handle username/password authentication"""
    auth_request = wrapper.recv(BUFSIZE)
    if auth_request[0:1] != b'\x01':
        return False
    username_len = auth_request[1]
    username = auth_request[2:2 + username_len].decode()
    password_len = auth_request[2 + username_len]
    password = auth_request[3 + username_len:3 + username_len + password_len].decode()
    
    if username == USERNAME and password == PASSWORD:
        wrapper.sendall(b'\x01\x00')  # Authentication success
        return True
    else:
        wrapper.sendall(b'\x01\x01')  # Authentication failed
        return False

def subnegotiation(wrapper):
    identification_packet = wrapper.recv(BUFSIZE)
    if VER != identification_packet[0:1]:
        return False
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    
    if b'\x02' in methods:
        wrapper.sendall(VER + M_USERPASS)
        return authenticate(wrapper)
    else:
        wrapper.sendall(VER + M_NOTAVAILABLE)
        return False

def connection(wrapper):
    if subnegotiation(wrapper):
        request(wrapper)

def request(wrapper):
    s5_request = wrapper.recv(BUFSIZE)
    if s5_request[0:1] != VER or s5_request[1:2] != CMD_CONNECT:
        return
    dst_addr = socket.inet_ntoa(s5_request[4:-2])
    dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    socket_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        socket_dst.connect((dst_addr, dst_port))
        wrapper.sendall(VER + b'\x00' + b'\x00' + ATYP_IPV4 + socket.inet_aton(dst_addr) + pack('>H', dst_port))
        proxy_loop(wrapper, socket_dst)
    except:
        wrapper.close()

def proxy_loop(socket_src, socket_dst):
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error:
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error:
            return

def main():
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    new_socket.bind((LOCAL_ADDR, LOCAL_PORT))
    new_socket.listen(10)
    signal(SIGINT, lambda s, f: EXIT.set_status(True))
    signal(SIGTERM, lambda s, f: EXIT.set_status(True))
    
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        Thread(target=connection, args=(wrapper,)).start()
    new_socket.close()

if __name__ == '__main__':
    main()
