import gdb
import socket
import pickle

def get_ida_symbols():
    IDA_HOST = '10.113.208.101'
    PORT = 50216

    try:
        sock = socket.create_connection((IDA_HOST, PORT))
    except:
        sys.exit(1)

    sock.send(bytes('GETSYM', 'UTF-8'))
    buf = bytes()
    while True:
        tmp = sock.recv(4096)
        buf += tmp
        if not tmp:
            break

    with open('/tmp/symfile', 'wb') as f:
        f.write(buf)
    gdb.execute('symbol-file /tmp/symfile')
