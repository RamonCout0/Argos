# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller — gera o Argos.exe com o ícone do olho e a interface embutida.
# Como usar (no Windows, com Python instalado):
#     pip install pyinstaller pywebview
#     pyinstaller argos.spec
# Sai: dist/Argos.exe  (um arquivo só, janela sem console, ícone do olho).
#
# Obs.: os scanners externos (gitleaks, semgrep, nmap, Ollama...) NÃO vão dentro
# do exe — são instalados à parte pelo instalar.ps1. O Argos acha cada um no PATH.

from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ['argos_app.py'],
    pathex=[],
    binaries=[],
    # a interface (html/css/js/olho/favicon) precisa viajar junto:
    datas=[('argos/ui/web', 'argos/ui/web')],
    hiddenimports=collect_submodules('webview'),   # backends do pywebview
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Argos',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,                       # sem a janelinha preta
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='argos/ui/web/favicon.ico',     # o olho na barra de tarefas / alt-tab
)
