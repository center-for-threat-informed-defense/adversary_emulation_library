# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['lazagne.py'],
             pathex=['C:\\Users\\garunagiri\\Documents\\Projects\\r4_dev\\sandworm\\Resources\\browser-creds\\Windows'],
             binaries=[],
             datas=[],
             hiddenimports=['lazagne.softwares.browsers.chromium_based', 'lazagne.softwares.browsers.chromium_browsers', 'lazagne.softwares.browsers.mozilla', 'lazagne.softwares.browsers.firefox_browsers', 'lazagne.softwares.browsers.ie', 'lazagne.softwares.browsers.ucbrowser', 'lazagne.softwares.windows.windows', 'lazagne.softwares.windows.credman', 'lazagne.config.constant', 'lazagne.config.module_info', 'lazagne.config.soft_import_module', 'lazagne.config.crypto.pyDes', 'lazagne.config.crypto.pyaes', 'lazagne.config.dico', 'lazagne.config.winstructure'],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='lazagne',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )
