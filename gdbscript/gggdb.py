from __future__ import print_function
import gdb
import socket
import pickle
import os
import subprocess as sp
import sys

IDA_HOST = '10.113.208.101'
PORT = 56746
TMPDIR = '/tmp/iddaa'

def connect_ida():
    if not os.path.exists(TMPDIR):
        os.mkdir(TMPDIR)
    try:
        sock = socket.create_connection((IDA_HOST, PORT), timeout=3)
        return sock
    except socket.error as err:
        sys.stderr.write("[ERROR] {}\n".format(err))
        return None

def show_result(result):
    try:
        f = open('{}/result'.format(TMPDIR), 'w')
        f.write(result)
        f.close()
    except err:
        sys.stderr.write("[ERROR] {}\n".format(''))
        return
    gdb.execute('shell vim {}/result'.format(TMPDIR))

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

    with open('{}/symfile'.format(TMPDIR), 'wb') as f:
        f.write(buf)

    if os.path.exists('{}/symfile'.format(TMPDIR)):
        gdb.execute('symbol-file {}/symfile'.format(TMPDIR))
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

    send(sock, 'GETLOCALTYPE')
    buf = recv(sock, True)
    local_type = pickle.loads(buf)
    with open('{}/localtype.h'.format(TMPDIR), 'wb') as f:
        f.write(bytes(local_type['header'], 'UTF-8'))
    with open('{}/localtype.cpp'.format(TMPDIR), 'wb') as f:
        f.write(bytes(local_type['source'], 'UTF-8'))
    cwd = os.getcwd()
    os.chdir(TMPDIR)
    if sp.check_call('g++ -c -g localtype.cpp'.split(' ')) == 0:
        gdb.execute('add-symbol-file {}/localtype.o 0'.format(TMPDIR))
    else:
        print('Generate symbol file failed')
    os.chdir(cwd)

class IDAPYTHON(gdb.Command):
    """ IDA python script wrapper"""
    def __init__(self):
        super(IDAPYTHON, self).__init__('idapython', gdb.COMMAND_USER)
    def invoke(self, args, from_tty):
        if args == 'cheatsheet':
            self.__cheatsheet()
            return

        sock = connect_ida()
        if not sock: return

        send(sock, 'EXECFILE')
        buf = ''
        try:
            f = open(args, 'r')
            buf = f.read()
        except:
            print('[ERROR] File not found.')
            return
        send(sock, buf)
        show_result(recv(sock))

    def __cheatsheet(self):
        print('IDA python Cheat Sheet')
        print()
        print('idc MakeComm(addr, comment)')
        print('----------------------------------------')
        print('Add comment at specified address.')
        print('Ex: idc MakeComm(0x804ddaa, \'Soy Sauce\')')
        print()
        print('idc SetColor(addr, what, color)')
        print('----------------------------------------')
        print('Set color for specified area')
        print('Ex: idc SetColor(0x0804ddaa, 1, 0xaabbcc) // address only')
        print('    idc SetColor(0x0804ddaa, 2, 0xaabbcc) // entire function')
        print('    idc SetColor(0x0804ddaa, 3, 0xaabbcc) // entire segment')
        print()


class IDARPC(gdb.Command):
    """ IDA python command wrapper"""
    def __init__(self, name):
        super(IDARPC, self).__init__(name, gdb.COMMAND_USER)
        self.name = name

    def invoke(self, args, from_tty):
        sock = connect_ida()
        if not sock: return

        send(sock, 'EXEC {}.{}'.format(self.name, args))
        show_result(recv(sock))

IDAPYTHON()
IDARPC('idautils')
IDARPC('idaapi')
IDARPC('idc')
