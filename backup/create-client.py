#!/usr/bin/env python3
"""Create an isolated backup client; never modify an existing Python installation."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--objection', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
manifest = json.loads((root / 'build_manifest.json').read_text())
environment = root / 'client-env'
if environment.exists():
    raise SystemExit('client-env already exists; no files were changed')
if sys.version_info[:2] != (3, 8):
    raise SystemExit('Run this with pyenv 3.8.13, as used by the working client')
subprocess.run([sys.executable, '-m', 'venv', str(environment)], check=True)
python = str(environment / 'bin/python')
packages = ['frida==16.1.4', 'frida-tools==12.3.0']
if args.objection:
    packages.append('objection==1.11.0')
subprocess.run([python, '-m', 'pip', 'install', *packages], check=True)
native = subprocess.check_output([python, '-c', 'import _frida;print(_frida.__file__)'], text=True).strip()
subprocess.run([python, str(Path(__file__).with_name('patch-client.py')),
                '--manifest', str(root / 'build_manifest.json'), native], check=True)
if args.objection:
    agent = subprocess.check_output([python, '-c',
        'import pathlib,objection;print(pathlib.Path(objection.__file__).parent / "agent.js")'], text=True).strip()
    path = Path(agent)
    original = path.read_text()
    title = manifest['alias_title']
    patched = original.replace('Frida.heapSize', f'globalThis.{title}.heapSize').replace(
        'Frida.version', f'globalThis.{title}.version')
    if original == patched:
        raise SystemExit('Unrecognized Objection agent; refusing to claim compatibility')
    path.with_suffix('.js.original').write_text(original)
    path.write_text(patched)
subprocess.run([python, '-c', 'import frida;assert frida.__version__ == "16.1.4";print(frida.__version__)'], check=True)
print('Created isolated client:', environment)
