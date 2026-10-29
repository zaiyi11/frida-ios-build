#!/usr/bin/env python3
"""Embed one Runner-owned bootstrap. Fail on source drift; preserve PAC backend."""
import argparse
import json
from pathlib import Path
import re


def embed(root, alias):
    if re.fullmatch(r'[a-z][a-z0-9]{4}', alias) is None:
        raise ValueError('alias must match [a-z][a-z0-9]{4}')
    source = (Path(__file__).parent / 'guard.js').read_text().replace('__BUILD_ALIAS__', alias)
    path = root / 'frida-core/lib/agent/agent.vala'
    text = path.read_text()
    if 'backup_guard' in text:
        raise ValueError('bootstrap already installed; use a clean source tree')

    def change(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise ValueError('source anchor missing/ambiguous: ' + old[:100])
        text = text.replace(old, new, 1)

    change('\t\tprivate bool unloading = false;',
           '\t\tprivate bool unloading = false;\n\t\tprivate ScriptEngine? backup_guard;')
    change('\t\t\ttry {\n\t\t\t\tyield setup_connection_with_transport_uri (transport_uri);',
           '\t\t\ttry {\n'
           '\t\t\t\tbackup_guard = new ScriptEngine (this);\n'
           '\t\t\t\tbackup_guard.message_from_script.connect ((id, message, data) => {\n'
           '\t\t\t\t\tif (message.contains ("\\\"type\\\":\\\"error\\\""))\n'
           '\t\t\t\t\t\tprinterr ("Bootstrap error: %s\\n", message);\n'
           '\t\t\t\t});\n'
           '\t\t\t\tvar options = new ScriptOptions ();\n'
           '\t\t\t\toptions.name = "bootstrap";\n'
           '\t\t\t\toptions.runtime = ScriptRuntime.QJS;\n'
           '\t\t\t\tvar instance = yield backup_guard.create_script (' + json.dumps(source, ensure_ascii=True) + ', null, options);\n'
           '\t\t\t\tyield backup_guard.load_script (instance.script_id);\n'
           '\t\t\t\tyield setup_connection_with_transport_uri (transport_uri);')
    change('\t\t\tyield close_all_sessions ();',
           '\t\t\tyield close_all_sessions ();\n'
           '\t\t\tif (backup_guard != null) {\n'
           '\t\t\t\tyield backup_guard.close ();\n'
           '\t\t\t\tbackup_guard = null;\n'
           '\t\t\t}')
    change('\t\tprivate async void prepare_for_termination (TerminationReason reason) {',
           '\t\tprivate async void prepare_for_termination (TerminationReason reason) {\n'
           '\t\t\tif (backup_guard != null)\n'
           '\t\t\t\tyield backup_guard.prepare_for_termination (reason);')
    change('\t\tprivate void unprepare_for_termination () {',
           '\t\tprivate void unprepare_for_termination () {\n'
           '\t\t\tif (backup_guard != null)\n'
           '\t\t\t\tbackup_guard.unprepare_for_termination ();')
    path.write_text(text)
    return source


def runtime_catalog(root):
    # Only registered GObject names are selected. CModule public headers and
    # gum_* function names remain compatible and are explicitly audited.
    names = set()
    for path in (root / 'frida-gum').rglob('*'):
        if path.suffix not in ('.c', '.cpp', '.h'):
            continue
        text = path.read_text(errors='replace')
        names.update(re.findall(r'G_DEFINE_(?:TYPE|INTERFACE)[A-Z_]*\s*\(\s*(Gum\w+)\s*,', text))
        names.update(re.findall(r'typedef\s+enum(?:\s+\w+)?\s*\{[^}]*\}\s*(Gum\w+)\s*;', text))
    return {'gobject_names': sorted(names),
            'extra_thread_names': ['gum-exceptor-worker', 'gum-%d']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('--alias', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(embed(args.source, args.alias))
    catalog = runtime_catalog(args.source)
    (Path(__file__).parent / 'runtime_catalog.json').write_text(json.dumps(catalog, indent=2))
