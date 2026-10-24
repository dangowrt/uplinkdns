import ctypes
import errno
import ipaddress
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

DNS_PORT = 15353
ECHO_PORT = 18080


def name(label):
    return label + '.uplinkdns.invalid'


CONFIG = {
    'dns_port': DNS_PORT,
    'echo_port': ECHO_PORT,
    'dns': {
        '127.0.0.53': {name('test'): ['127.0.0.10'],
                       name('multi'): ['127.0.0.10', '127.0.0.12']},
        '127.0.0.54': {name('test'): ['127.0.0.11', 'txt:hello-b'],
                       '11.0.0.127.in-addr.arpa': ['ptr:' + name('host-b')]},
        '::1': {name('test'): ['127.0.0.13'],
                name('six'): ['::1'],
                name('closed'): ['127.0.0.13']},
    },
    'echo': ['127.0.0.10', '127.0.0.11', '127.0.0.12', '127.0.0.13', '::1'],
    'uplink_b': '127.0.0.3;dns=127.0.0.54:%d' % DNS_PORT,
}

UPLINKS = ' '.join([
    '127.0.0.2;dns=127.0.0.53:%d' % DNS_PORT,
    CONFIG['uplink_b'],
    'lo;dns=[::1]:%d' % DNS_PORT,
    '127.0.0.4;dns=[::1]:%d' % DNS_PORT,
    '127.0.1.0/24;dns=127.0.0.54:%d' % DNS_PORT,
])

HOST_NOT_FOUND = 1

failures = []


def glibc():
    return hasattr(ctypes.CDLL(None), 'gnu_get_libc_version')


def check(label, ok, detail):
    print('%s %s: %s' % ('PASS' if ok else 'FAIL', label, detail))
    if not ok:
        failures.append(label)


def synthetic_ok(result):
    v4 = [a for a in result['addrs'] if ':' not in a]
    v6 = [a for a in result['addrs'] if ':' in a]
    in_v4 = all(ipaddress.ip_address(a) in
                ipaddress.ip_network('198.18.0.0/15') for a in v4)
    in_v6 = all(a.startswith('fd') for a in v6)
    named = all(n == name('test') for n in result['names'])
    return len(v4) == 1 and len(v6) == 1 and in_v4 and in_v6 and named


def isolated_run(lib):
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'isolated.py')
    env = dict(os.environ, LD_PRELOAD=lib,
               UPLINKDNS_UPLINKS='lo;dns=127.0.0.53:%d' % DNS_PORT)
    out = subprocess.run([sys.executable, '-I', script, name('test'),
                          str(ECHO_PORT)], env=env, stdout=subprocess.PIPE,
                         check=True)
    return json.loads(out.stdout)


def main():
    lib = os.path.abspath(sys.argv[1])
    iso = isolated_run(lib)
    check('family_v6_refused', iso['no_v6'] == 'error:ENETUNREACH',
          iso['no_v6'])
    check('family_v4_refused', iso['no_v4'] == 'error:ENETUNREACH',
          iso['no_v4'])

    log = servers.start(CONFIG)

    with tempfile.NamedTemporaryFile('w', suffix='.json') as cfg:
        json.dump(CONFIG, cfg)
        cfg.flush()
        env = dict(os.environ, LD_PRELOAD=lib, UPLINKDNS_UPLINKS=UPLINKS)
        client = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'client.py')
        out = subprocess.run([sys.executable, '-I', client, cfg.name],
                             env=env, stdout=subprocess.PIPE, check=True)
    r = json.loads(out.stdout)

    check('bound_a', r['bound_a'] == '127.0.0.10', r['bound_a'])
    check('bound_b', r['bound_b'] == '127.0.0.11', r['bound_b'])
    check('synthetic', synthetic_ok(r['synthetic']), r['synthetic'])
    check('unbound_system', r['unbound_system'] == 'error:EHOSTUNREACH',
          r['unbound_system'])
    check('nxdomain_uplink', r['nxdomain_uplink'] == 'error:EHOSTUNREACH',
          r['nxdomain_uplink'])
    check('rotation', r['rotation'] == ['127.0.0.10', '127.0.0.12'],
          r['rotation'])
    check('udp', r['udp'] == '127.0.0.10', r['udp'])
    check('udp_batch', r['udp_batch'] == ['127.0.0.10', '127.0.0.10'],
          r['udp_batch'])
    check('device_v6', r['device_v6'] == '::1', r['device_v6'])
    check('mapped_slots',
          r['mapped_slots'] == ['error:EHOSTUNREACH', '127.0.0.13'],
          r['mapped_slots'])
    check('fail_closed', r['fail_closed'].startswith('error:'),
          r['fail_closed'])
    check('explicit_api', r['explicit_api'] ==
          {'api': '127.0.0.11', 'context': '127.0.0.11',
           'system': 'gaierror', 'name': name('test'),
           'name_other': -errno.ENOENT, 'covering': True},
          r['explicit_api'])
    check('forked', r['forked'] == '127.0.0.10', r['forked'])
    check('hostent', r['hostent'] ==
          {'defer_synthetic': True, 'defer_connect': '127.0.0.10',
           'defer_name': name('test'), 'defer6': True, 'python_ex': True,
           'context': ['127.0.0.11'], 'reverse': name('host-b'),
           'getnameinfo': name('host-b'),
           'python_gethostbyaddr': name('host-b'), 'erange': errno.ERANGE},
          r['hostent'])
    check('query', r['query'] ==
          {'res_query': 'hello-b', 'res_search': 'hello-b',
           'res_missing': [-1, HOST_NOT_FOUND], 'res_send': [True, 'hello-b'],
           'res_truncated': True}, r['query'])
    if glibc():
        check('async', r['async'] ==
              {'defer': True, 'wait_ret': 0, 'wait': '127.0.0.11',
               'nowait_ret': 0, 'suspend': 0, 'error': 0,
               'nowait': '127.0.0.11'}, r['async'])
    else:
        check('async', r['async'] == 'not glibc', r['async'])

    sources = {(q['server'], q['client']) for q in log
               if q['name'] == name('test')}
    check('query_source_a', ('127.0.0.53', '127.0.0.2') in sources, sources)
    check('query_source_b', ('127.0.0.54', '127.0.0.3') in sources, sources)
    wrong = [q for q in log if (q['server'], q['client']) not in
             {('127.0.0.53', '127.0.0.2'), ('127.0.0.54', '127.0.0.3'),
              ('::1', '::1')}]
    check('no_stray_queries', not wrong, wrong)
    check('fail_closed_silent',
          not [q for q in log if q['name'] == name('closed')],
          [q for q in log if q['name'] == name('closed')])

    print('%d failure(s)' % len(failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
