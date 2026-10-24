import ctypes
import errno
import json
import os
import socket
import struct
import sys

SO_BINDTODEVICE = 25
CTX_DEFER = -1
CTX_SYSTEM = -2

config = json.load(open(sys.argv[1]))
port = config['echo_port']
results = {}


def name(label):
    return label + '.uplinkdns.invalid'


def outcome(func):
    try:
        return func()
    except OSError as e:
        return 'error:' + errno.errorcode.get(e.errno, str(e.errno))


def stream_bound(src, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.connect((host, port))
    reply = s.recv(64).decode()
    s.close()
    return reply


def stream_device(dev, family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
    s.connect(addr)
    reply = s.recv(64).decode()
    s.close()
    return reply


def datagram_bound(src, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.sendto(b'x', (host, port))
    reply = s.recvfrom(64)[0].decode()
    s.close()
    return reply


def synthetic():
    infos = socket.getaddrinfo(name('test'), port, 0, socket.SOCK_STREAM)
    addrs = [i[4][0] for i in infos]
    names = [socket.getnameinfo(i[4], 0)[0] for i in infos]
    return {'addrs': addrs, 'names': names}


def mapped_slots():
    infos = socket.getaddrinfo(name('test'), port, socket.AF_INET6,
                               socket.SOCK_STREAM, 0, socket.AI_V4MAPPED)
    out = []
    for info in infos:
        out.append(outcome(lambda: stream_device('lo', socket.AF_INET6,
                                                 info[4])))
    return out


class AddrInfo(ctypes.Structure):
    pass


AddrInfo._fields_ = [('ai_flags', ctypes.c_int),
                     ('ai_family', ctypes.c_int),
                     ('ai_socktype', ctypes.c_int),
                     ('ai_protocol', ctypes.c_int),
                     ('ai_addrlen', ctypes.c_uint32),
                     ('ai_addr', ctypes.c_void_p),
                     ('ai_canonname', ctypes.c_char_p),
                     ('ai_next', ctypes.POINTER(AddrInfo))]


def explicit_api():
    lib = ctypes.CDLL(None)
    uplink = lib.uplinkdns_uplink_add(config['uplink_b'].encode())
    res = ctypes.POINTER(AddrInfo)()
    ret = lib.uplinkdns_getaddrinfo(uplink, name('test').encode(), None,
                                    None, ctypes.byref(res))
    if ret:
        return 'eai:%d' % ret
    raw = ctypes.string_at(res.contents.ai_addr, 8)
    lib.uplinkdns_freeaddrinfo(res)
    first = socket.inet_ntop(socket.AF_INET, raw[4:8])

    lib.uplinkdns_context_set(uplink)
    infos = socket.getaddrinfo(name('test'), port, socket.AF_INET)
    in_context = infos[0][4][0]
    lib.uplinkdns_context_set(CTX_SYSTEM)
    system = outcome(lambda: socket.getaddrinfo(name('test'), port,
                                                socket.AF_INET)[0][4][0])
    if system.startswith('error'):
        system = 'gaierror'
    lib.uplinkdns_context_set(CTX_DEFER)

    infos = socket.getaddrinfo(name('test'), port, socket.AF_INET)
    raw = socket.inet_pton(socket.AF_INET, infos[0][4][0])
    sin = struct.pack('=H', socket.AF_INET) + struct.pack('>H', port) + raw
    sin += bytes(16 - len(sin))
    buf = ctypes.create_string_buffer(256)
    synthetic = lib.uplinkdns_name_get(sin, len(sin), buf, len(buf))
    found = buf.value.decode() if not synthetic else synthetic
    real = struct.pack('=H', socket.AF_INET) + struct.pack('>H', port)
    real += socket.inet_pton(socket.AF_INET, '127.0.0.1') + bytes(8)
    other = lib.uplinkdns_name_get(real, len(real), buf, len(buf))
    return {'api': first, 'context': in_context, 'system': system,
            'name': found, 'name_other': other}


def forked():
    rfd, wfd = os.pipe()
    pid = os.fork()
    if not pid:
        os.close(rfd)
        os.write(wfd, outcome(lambda: stream_bound('127.0.0.2',
                                                   name('test'))).encode())
        os._exit(0)
    os.close(wfd)
    reply = os.read(rfd, 64).decode()
    os.waitpid(pid, 0)
    return reply


def system_unbound():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    infos = socket.getaddrinfo(name('test'), port, socket.AF_INET)
    try:
        s.connect(infos[0][4])
    finally:
        s.close()
    return 'connected'


results['bound_a'] = outcome(lambda: stream_bound('127.0.0.2', name('test')))
results['bound_b'] = outcome(lambda: stream_bound('127.0.0.3', name('test')))
results['synthetic'] = synthetic()
results['unbound_system'] = outcome(system_unbound)
results['nxdomain_uplink'] = outcome(
    lambda: stream_bound('127.0.0.2', name('missing')))
results['rotation'] = sorted(
    {outcome(lambda: stream_bound('127.0.0.2', name('multi')))
     for _ in range(4)})
results['udp'] = outcome(lambda: datagram_bound('127.0.0.2', name('test')))
results['device_v6'] = outcome(
    lambda: stream_device('lo', socket.AF_INET6, (name('six'), port)))
results['mapped_slots'] = mapped_slots()
results['fail_closed'] = outcome(
    lambda: stream_bound('127.0.0.4', name('closed')))
results['explicit_api'] = explicit_api()
results['forked'] = forked()

print(json.dumps(results))
