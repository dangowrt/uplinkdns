import json
import socket
import struct
import threading

QTYPE_A = 1
QTYPE_PTR = 12
QTYPE_TXT = 16
QTYPE_AAAA = 28
RCODE_NXDOMAIN = 3


def name_read(msg, off):
    labels = []
    while msg[off]:
        n = msg[off]
        labels.append(msg[off + 1:off + 1 + n].decode())
        off += n + 1
    return '.'.join(labels).lower(), off + 1


def name_encode(name):
    out = b''
    for label in name.split('.'):
        out += bytes([len(label)]) + label.encode()
    return out + b'\0'


def rdata_list(values, qtype):
    out = []
    for value in values:
        if value.startswith('ptr:'):
            if qtype == QTYPE_PTR:
                out.append(name_encode(value[4:]))
        elif value.startswith('txt:'):
            if qtype == QTYPE_TXT:
                text = value[4:].encode()
                out.append(bytes([len(text)]) + text)
        elif qtype == QTYPE_A and ':' not in value:
            out.append(socket.inet_pton(socket.AF_INET, value))
        elif qtype == QTYPE_AAAA and ':' in value:
            out.append(socket.inet_pton(socket.AF_INET6, value))
    return out


def answer_build(msg, records):
    qid, = struct.unpack('>H', msg[:2])
    name, off = name_read(msg, 12)
    qtype, = struct.unpack('>H', msg[off:off + 2])
    question = msg[12:off + 4]
    if name not in records:
        flags = 0x8180 | RCODE_NXDOMAIN
        return name, qtype, struct.pack('>HHHHHH', qid, flags, 1, 0, 0, 0) + question
    rdatas = rdata_list(records[name], qtype)
    out = b''
    for rdata in rdatas:
        out += struct.pack('>HHHIH', 0xc00c, qtype, 1, 60, len(rdata)) + rdata
    head = struct.pack('>HHHHHH', qid, 0x8180, 1, len(rdatas), 0, 0)
    return name, qtype, head + question + out


class Dns(threading.Thread):
    def __init__(self, addr, port, records, log):
        super().__init__(daemon=True)
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((addr, port))
        self.addr = addr
        self.records = records
        self.log = log

    def run(self):
        while True:
            msg, peer = self.sock.recvfrom(4096)
            name, qtype, reply = answer_build(msg, self.records)
            self.log.append({'server': self.addr, 'client': peer[0],
                             'name': name, 'type': qtype})
            self.sock.sendto(reply, peer)


class Echo(threading.Thread):
    def __init__(self, addr, port, kind):
        super().__init__(daemon=True)
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        self.sock = socket.socket(family, kind)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((addr, port))
        self.addr = addr
        self.kind = kind
        if kind == socket.SOCK_STREAM:
            self.sock.listen(16)

    def run(self):
        while True:
            if self.kind == socket.SOCK_DGRAM:
                _, peer = self.sock.recvfrom(4096)
                self.sock.sendto(self.addr.encode(), peer)
                continue
            conn, _ = self.sock.accept()
            conn.sendall(self.addr.encode())
            conn.close()


def start(config):
    log = []
    for server, records in config['dns'].items():
        Dns(server, config['dns_port'], records, log).start()
    for addr in config['echo']:
        Echo(addr, config['echo_port'], socket.SOCK_STREAM).start()
        Echo(addr, config['echo_port'], socket.SOCK_DGRAM).start()
    return log


if __name__ == '__main__':
    import sys
    start(json.load(open(sys.argv[1])))
    threading.Event().wait()
