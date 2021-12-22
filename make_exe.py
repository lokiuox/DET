#!/usr/bin/env python3

template ="""# -*- mode: python -*-

block_cipher = None

import sys
sys.modules['FixTk'] = None
	
a = Analysis(['cli.py'],
             pathex=['.'],
             binaries=[],
             datas=[('det', 'det'), ('det/plugins', 'det/plugins')],
             hiddenimports=['det', 'det.plugins', 'det.plugins.res' {plugins}],
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
"""

import det
plugins = [f"'det.plugins.{x}'" for x in det.plugins.available()]
specfile = template.format(plugins=',' + ','.join(plugins))
with open("det.spec", "w") as f:
    f.write(specfile)

import PyInstaller.__main__
import os
import shutil
workdir = os.getcwd()
det_spec = os.path.join(workdir, 'det.spec')
distdir = workdir
builddir = os.path.join(workdir, 'build')
PyInstaller.__main__.run(['--distpath', distdir, '--workpath', builddir, det_spec])
shutil.rmtree(builddir, ignore_errors=True)
input("=== Done. Press any key to exit. ===")
