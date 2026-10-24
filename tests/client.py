import ctypes
import errno
import ipaddress
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


class IoVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('len', ctypes.c_size_t)]


class MsgHdr(ctypes.Structure):
    _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint32),
                ('iov', ctypes.POINTER(IoVec)), ('iovlen', ctypes.c_size_t),
                ('control', ctypes.c_void_p), ('controllen', ctypes.c_size_t),
                ('flags', ctypes.c_int)]


class MMsgHdr(ctypes.Structure):
    _fields_ = [('hdr', MsgHdr), ('len', ctypes.c_uint)]


def datagram_batch(src, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    addr = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    sin = struct.pack('=H', socket.AF_INET) + struct.pack('>H', port)
    sin += socket.inet_pton(socket.AF_INET, addr) + bytes(8)
    name_buf = ctypes.create_string_buffer(sin, len(sin))
    payload = ctypes.create_string_buffer(b'x', 1)
    iov = IoVec(ctypes.cast(payload, ctypes.c_void_p), 1)
    msgs = (MMsgHdr * 2)()
    for m in msgs:
        m.hdr.name = ctypes.cast(name_buf, ctypes.c_void_p)
        m.hdr.namelen = len(sin)
        m.hdr.iov = ctypes.pointer(iov)
        m.hdr.iovlen = 1
    sent = ctypes.CDLL(None, use_errno=True).sendmmsg(s.fileno(), msgs, 2, 0)
    if sent < 0:
        s.close()
        raise OSError(ctypes.get_errno(), 'sendmmsg')
    replies = [s.recvfrom(64)[0].decode() for _ in range(sent)]
    s.close()
    return replies


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


class HostEnt(ctypes.Structure):
    _fields_ = [('h_name', ctypes.c_char_p),
                ('h_aliases', ctypes.POINTER(ctypes.c_char_p)),
                ('h_addrtype', ctypes.c_int),
                ('h_length', ctypes.c_int),
                ('h_addr_list', ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)))]


class GaiCb(ctypes.Structure):
    _fields_ = [('ar_name', ctypes.c_char_p),
                ('ar_service', ctypes.c_char_p),
                ('ar_request', ctypes.c_void_p),
                ('ar_result', ctypes.POINTER(AddrInfo)),
                ('ret', ctypes.c_int),
                ('reserved', ctypes.c_int * 5)]


def libc():
    lib = ctypes.CDLL(None)
    for func in ('gethostbyname', 'gethostbyname2', 'gethostbyaddr'):
        getattr(lib, func).restype = ctypes.POINTER(HostEnt)
    lib.__h_errno_location.restype = ctypes.POINTER(ctypes.c_int)
    return lib


def hostent_addrs(he):
    family = socket.AF_INET if he.h_length == 4 else socket.AF_INET6
    out = []
    i = 0
    while he.h_addr_list[i]:
        raw = bytes(he.h_addr_list[i][:he.h_length])
        out.append(socket.inet_ntop(family, raw))
        i += 1
    return out


def in_synthetic(addr):
    return ipaddress.ip_address(addr) in ipaddress.ip_network('198.18.0.0/15')


def hostent_tests():
    lib = libc()
    out = {}
    he = lib.gethostbyname(name('test').encode()).contents
    addr = hostent_addrs(he)[0]
    out['defer_synthetic'] = in_synthetic(addr)
    out['defer_connect'] = outcome(lambda: stream_bound('127.0.0.2', addr))
    rev = lib.gethostbyaddr(socket.inet_pton(socket.AF_INET, addr), 4,
                            socket.AF_INET)
    out['defer_name'] = rev.contents.h_name.decode()
    he6 = lib.gethostbyname2(name('test').encode(), socket.AF_INET6).contents
    out['defer6'] = hostent_addrs(he6)[0].startswith('fd')
    out['python_ex'] = in_synthetic(socket.gethostbyname_ex(name('test'))[2][0])

    lib.uplinkdns_context_set(lib.uplinkdns_uplink_add(config['uplink_b'].encode()))
    out['context'] = hostent_addrs(lib.gethostbyname(name('test').encode()).contents)
    rev = lib.gethostbyaddr(socket.inet_pton(socket.AF_INET, '127.0.0.11'), 4,
                            socket.AF_INET)
    out['reverse'] = rev.contents.h_name.decode() if rev else 'null'
    out['getnameinfo'] = outcome(lambda: socket.getnameinfo(
        ('127.0.0.11', port), socket.NI_NAMEREQD)[0])
    out['python_gethostbyaddr'] = outcome(
        lambda: socket.gethostbyaddr('127.0.0.11')[0])
    he = HostEnt()
    result = ctypes.POINTER(HostEnt)()
    err = ctypes.c_int()
    buf = ctypes.create_string_buffer(8)
    out['erange'] = lib.gethostbyname_r(name('test').encode(), ctypes.byref(he),
                                        buf, len(buf), ctypes.byref(result),
                                        ctypes.byref(err))
    lib.uplinkdns_context_set(CTX_DEFER)
    return out


def txt_read(msg):
    off = 12
    while msg[off]:
        off += msg[off] + 1
    off += 5
    if struct.unpack('>H', msg[6:8])[0] == 0:
        return None
    off += 2 + 8
    rdlen, = struct.unpack('>H', msg[off:off + 2])
    rdata = msg[off + 2:off + 2 + rdlen]
    return rdata[1:1 + rdata[0]].decode()


def query_build(qid, qname, qtype):
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    for label in qname.split('.'):
        q += bytes([len(label)]) + label.encode()
    return q + b'\0' + struct.pack('>HH', qtype, 1)


def query_tests():
    lib = libc()
    c_in, t_txt = 1, 16
    buf = ctypes.create_string_buffer(512)
    out = {}
    lib.uplinkdns_context_set(lib.uplinkdns_uplink_add(config['uplink_b'].encode()))
    n = lib.res_query(name('test').encode(), c_in, t_txt, buf, len(buf))
    out['res_query'] = txt_read(buf.raw[:n]) if n > 0 else n
    n = lib.res_search(name('test').encode(), c_in, t_txt, buf, len(buf))
    out['res_search'] = txt_read(buf.raw[:n]) if n > 0 else n
    n = lib.res_query(name('missing').encode(), c_in, t_txt, buf, len(buf))
    out['res_missing'] = [n, lib.__h_errno_location().contents.value]
    query = query_build(0x4242, name('test'), t_txt)
    n = lib.res_send(query, len(query), buf, len(buf))
    out['res_send'] = [struct.unpack('>H', buf.raw[:2])[0] == 0x4242,
                       txt_read(buf.raw[:n]) if n > 0 else n]
    out['res_truncated'] = lib.res_query(name('test').encode(), c_in, t_txt,
                                         buf, 12) > 12
    lib.uplinkdns_context_set(CTX_DEFER)
    return out


def gai_first(req):
    raw = ctypes.string_at(req.ar_result.contents.ai_addr, 8)
    return socket.inet_ntop(socket.AF_INET, raw[4:8])


def async_tests():
    lib = libc()
    gai_wait, gai_nowait = 0, 1
    if not hasattr(lib, 'gnu_get_libc_version'):
        return 'not glibc'

    hints = AddrInfo()
    hints.ai_family = socket.AF_INET
    hints.ai_socktype = socket.SOCK_STREAM
    out = {}

    req = GaiCb(name('test').encode(), None, ctypes.addressof(hints))
    reqs = (ctypes.POINTER(GaiCb) * 1)(ctypes.pointer(req))
    lib.getaddrinfo_a(gai_wait, reqs, 1, None)
    out['defer'] = in_synthetic(gai_first(req))

    lib.uplinkdns_context_set(lib.uplinkdns_uplink_add(config['uplink_b'].encode()))
    req = GaiCb(name('test').encode(), None, ctypes.addressof(hints))
    reqs = (ctypes.POINTER(GaiCb) * 1)(ctypes.pointer(req))
    out['wait_ret'] = lib.getaddrinfo_a(gai_wait, reqs, 1, None)
    out['wait'] = gai_first(req)

    req = GaiCb(name('test').encode(), None, ctypes.addressof(hints))
    reqs = (ctypes.POINTER(GaiCb) * 1)(ctypes.pointer(req))
    out['nowait_ret'] = lib.getaddrinfo_a(gai_nowait, reqs, 1, None)
    out['suspend'] = lib.gai_suspend(reqs, 1, None)
    out['error'] = lib.gai_error(ctypes.byref(req))
    out['nowait'] = gai_first(req)
    lib.uplinkdns_context_set(CTX_DEFER)
    return out


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
results['udp_batch'] = outcome(
    lambda: datagram_batch('127.0.0.2', name('test')))
results['device_v6'] = outcome(
    lambda: stream_device('lo', socket.AF_INET6, (name('six'), port)))
results['mapped_slots'] = mapped_slots()
results['fail_closed'] = outcome(
    lambda: stream_bound('127.0.0.4', name('closed')))
results['explicit_api'] = explicit_api()
results['forked'] = forked()
results['hostent'] = hostent_tests()
results['query'] = query_tests()
results['async'] = async_tests()

print(json.dumps(results))
