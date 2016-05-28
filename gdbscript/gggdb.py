from __future__ import print_function
import gdb
import socket
import pickle
import os
import subprocess as sp
import sys

IDA_HOST = '10.113.208.101'
PORT = 50216

def connect_ida():
    try:
        sock = socket.create_connection((IDA_HOST, PORT), timeout=3)
        return sock
    except socket.error as err:
        sys.stderr.write("[ERROR] {}\n".format(err))
        return None

def send(sock, buf):
    if sys.version_info < (3, 0):
        sock.send(buf)
    else:
        sock.send(bytes(buf, 'UTF-8'))

def recv(sock, raw=False):
    buf = bytes()
    while True:
        tmp = sock.recv(4096)
        buf += tmp
        if not tmp:
            break
    if raw:
        return buf
    else:
        return buf if sys.version_info < (3, 0) else buf.decode()

def get_ida_symbols():
    sock = connect_ida()
    if not sock: return 

    send(sock, 'GETSYM')
    buf = recv(sock, True)

    with open('/tmp/symfile', 'wb') as f:
        f.write(buf)

    if os.path.exists('/tmp/symfile'):
        gdb.execute('symbol-file /tmp/symfile')
    else:
        print('Can\'t not receive ida symfile.')

pseudo_code = dict()

def get_pseudo_code(func):
    global pseudo_code
    if func in pseudo_code.keys():
        print(pseudo_code[func])

    sock = connect_ida()
    if not sock: return

    send(sock, 'GETPSEUDOCODE {}'.format(func))
    code = recv(sock).strip()
    if 'Function not found' not in code:
        pseudo_code[func] = code
    print(pseudo_code[func])

def get_local_type():
    sock = connect_ida()
    if not sock: return

    sock.send(bytes('GETLOCALTYPE', 'UTF-8'))
    buf = recv(sock, True)
    local_type = pickle.loads(buf)
    with open('/tmp/localtype.h', 'wb') as f:
        f.write(bytes(local_type['header'], 'UTF-8'))
    with open('/tmp/localtype.cpp', 'wb') as f:
        f.write(bytes(local_type['source'], 'UTF-8'))
    cwd = os.getcwd()
    os.chdir('/tmp')
    if sp.check_call('g++ -c -g localtype.cpp'.split(' ')) == 0:
        gdb.execute('add-symbol-file /tmp/localtype.o 0') 
    else:
        print('Generate symbol file failed')