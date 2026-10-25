# SPDX-License-Identifier: GPL-2.0-or-later

import errno
import json
import os
import socket
import subprocess
import sys

SO_BINDTODEVICE = 25


def outcome(func):
    try:
        return func()
    except OSError as e:
        return 'error:' + errno.errorcode.get(e.errno, str(e.errno))


def netns_enter():
    if os.geteuid() == 0:
        os.unshare(os.CLONE_NEWNET)
        return

    uid = os.geteuid()
    gid = os.getegid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
    with open('/proc/self/setgroups', 'w') as f:
        f.write('deny')
    with open('/proc/self/uid_map', 'w') as f:
        f.write('0 %d 1' % uid)
    with open('/proc/self/gid_map', 'w') as f:
        f.write('0 %d 1' % gid)


def ip(*args):
    env = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD'}
    subprocess.run(['ip'] + list(args), env=env, check=True)


def device_connect(family, host, port):
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b'lo')
        s.connect(infos[0][4])
    finally:
        s.close()
    return 'connected'


def main():
    name, port = sys.argv[1], int(sys.argv[2])

    netns_enter()
    ip('link', 'set', 'lo', 'up')
    ip('addr', 'flush', 'dev', 'lo')

    print(json.dumps({
        'no_v6': outcome(lambda: device_connect(socket.AF_INET6, name, port)),
        'no_v4': outcome(lambda: device_connect(socket.AF_INET, name, port)),
    }))


main()
