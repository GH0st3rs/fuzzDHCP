#!/usr/bin/python3
from core import AlphaNumericFuzzer, NumericFuzzer
import socket
from argparse import ArgumentParser
import json
import time


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-t', dest='host', required=True, help='Target IP address')
    parser.add_argument('-p', dest='port', type=int, help='Target RTSP port (default: 554)', default=554)
    parser.add_argument('-c', dest='config', help='Config file (default: rtsp.json)', default='rtsp.json')
    return parser.parse_args()


def print_status(txt):
    print('[*] %s' % txt)


def log_event(req, resp, timer):
    file = open('LOG.TXT', 'a')
    if '401 Unauthorized' not in resp and len(resp) != 192:
        file.write('\n\n' + '-' * 100 + '\n')
        file.write('Request: %s\n' % req)
        file.write('Response: (%d) %s\n' % (len(resp), resp or '<None>'))
        file.write('Response time: %f\n' % timer)
    file.close()


def send(rhost, rport, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((rhost, rport))
        s.settimeout(5)
    except socket.error:
        if s:
            s.close()
        print("Could not open socket")
        return
    s.send(data)
    start_time = time.time()
    try:
        rcv = s.recv(1024)
    except socket.timeout:
        rcv = b'timeout'
    log_event(data.decode(), rcv.decode(), time.time() - start_time)
    s.close()


def generate_alnum_input(n):
    """
    Returns an alphanumeric string with a length no greater than n.
    """
    fuzzer = AlphaNumericFuzzer(0, n)
    return fuzzer.generate()


def generate_num_input(n):
    """
    Returns an numeric string with a length no greater than n.
    """
    fuzzer = NumericFuzzer(0, n)
    return fuzzer.generate()


def generate_input(n, vtype):
    if vtype == 'string':
        return generate_alnum_input(n)
    elif vtype == 'int':
        return generate_num_input(n)


def addParameter(param_name, value):
    return '%s: %s\r\n' % (param_name, value)


def setRequestType(parameter, uri, version):
    return '%s %s RTSP/%s\r\n' % (parameter, uri, version)


def fuzz_all_fields(rhost, rport, param, fields):
    static_fields = list(filter(lambda x: x['value'] != 'fuzz', fields))
    fuzz_fields = list(filter(lambda x: x['value'] == 'fuzz', fields))
    for x in range(10000):
        body = setRequestType(param, 'rtsp://%s:%s/onvif' % (rhost, rport), version='1.0')
        # add static fields
        for static in static_fields:
            body += addParameter(static['name'], static['value'])
        # add dinamic fuzzing fields
        for i in range(len(fuzz_fields)):
            name = fuzz_fields[i]['name']
            if name == 'Session':
                continue
            if i == x % len(fuzz_fields):
                value = generate_alnum_input(x)
            else:
                value = generate_alnum_input(10)
            body += addParameter(name, value)
        body += '\r\n'

        send(rhost, rport, body.encode())


def fuzz_one_field(rhost, rport, param, fields):
    # static_fields = list(filter(lambda x: x['value'] != 'fuzz', fields))
    fuzz_fields = list(filter(lambda x: x['value'] == 'fuzz', fields))
    for i in range(len(fuzz_fields)):
        for x in range(0, 10000, 100):
            body = setRequestType(param, 'rtsp://%s:%s/onvif' % (rhost, rport), version='1.0')
            name = fuzz_fields[i]['name']
            value = generate_input(x, fuzz_fields[i]['type'])
            body += addParameter(name, value)
            body += '\r\n'
            # Send payload
            send(rhost, rport, body.encode())


def fuzz_url(rhost, rport):
    for item in ['host', 'port', 'file', 'ver']:
        print('Fuzz url: %s' % item)
        for x in range(5000):
            if item == 'host':
                body = setRequestType('OPTIONS', 'rtsp://%s:%s/onvif' % (generate_alnum_input(x), rport), version='1.0')
            elif item == 'port':
                body = setRequestType('OPTIONS', 'rtsp://%s:%s/onvif' % (rhost, generate_alnum_input(x)), version='1.0')
            elif item == 'file':
                body = setRequestType('OPTIONS', 'rtsp://%s:%s/%s' % (rhost, rport, generate_alnum_input(x)), version='1.0')
            elif item == 'ver':
                body = setRequestType('OPTIONS', 'rtsp://%s:%s/onvif' % (rhost, rport), version=generate_alnum_input(x))
            body += 'CSeq: 1\r\n'
            body += 'User-Agent: VLC\r\n\r\n'

            send(rhost, rport, body.encode())


def main():
    args = parse_args()
    open('LOG.TXT', 'w').write('')
    config = json.load(open(args.config))
    global_fields = config.get('global_fields')

    # fuzz_url(args.host, args.port)

    for item in config.get('params'):
        print_status('Start fuzz %s' % item)
        fields = config.get('params')[item] + global_fields
        fuzz_one_field(args.host, args.port, item, fields)


if __name__ == '__main__':
    main()
