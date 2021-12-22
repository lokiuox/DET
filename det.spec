# -*- mode: python -*-

block_cipher = None

import sys
sys.modules['FixTk'] = None
	
a = Analysis(['cli.py'],
             pathex=['.'],
             binaries=[],
             datas=[('det', 'det'), ('det/plugins', 'det/plugins')],
             hiddenimports=['det', 'det.plugins', 'det.plugins.res' ,'det.plugins.dns','det.plugins.ftp','det.plugins.github_gist','det.plugins.gmail','det.plugins.google_docs','det.plugins.http','det.plugins.icmp','det.plugins.sip','det.plugins.slack','det.plugins.smtp','det.plugins.tcp','det.plugins.tcp_ipv6','det.plugins.twitter','det.plugins.udp','det.plugins.udp_ipv6','det.plugins.wifi'],
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
          upx=False,
          console=True )
