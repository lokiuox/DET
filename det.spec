# -*- mode: python -*-

block_cipher = None

import sys
sys.modules['FixTk'] = None

a = Analysis(['cli.py'],
             pathex=['.'],
             binaries=[],
             datas=[('det/plugins', 'plugins')],
             hiddenimports=['det'],
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
