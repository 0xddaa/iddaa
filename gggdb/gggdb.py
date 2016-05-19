import gdb
import socket
import pickle
import os

IDA_HOST = '10.113.208.101'
PORT = 50216

def connect_ida():
    try:
        sock = socket.create_connection((IDA_HOST, PORT), timeout=3)
        return sock
    except socket.error as err:
        sys.stderr.write("[ERROR] {}\n".format(err))
        return None

def recv(sock):
    buf = bytes()
    while True:
        tmp = sock.recv(4096)
        buf += tmp
        if not tmp:
            break
    return buf

def get_ida_symbols():
    sock = connect_ida()
    if not sock: return

    sock.send(bytes('GETSYM', 'UTF-8'))
    buf = recv(sock)

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

    sock.send(bytes('GETPSEUDOCODE {}'.format(func), 'UTF-8'))
    code = recv(sock).decode().strip()
    pseudo_code[func] = code
    print(pseudo_code[func])
