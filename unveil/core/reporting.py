import html
import json
import os
from pathlib import Path
import tempfile


def same_path(left, right):
    left, right = Path(left), Path(right)
    return left.resolve() == right.resolve() or (
        left.exists() and right.exists() and os.path.samefile(left, right))


def protect_output(output, inputs):
    if any(same_path(output, source) for source in inputs):
        raise ValueError('Output must not overwrite an input artifact')


def render(report, format='json'):
    serialized = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + '\n'
    if format == 'json':
        return serialized
    if format == 'html':
        return ('<!doctype html><html lang="pt-BR"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Unveil — relatório</title><style>body{max-width:1100px;margin:3rem auto;'
                'padding:0 1rem;font:16px system-ui;background:#111827;color:#e5e7eb}'
                'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1f2937;padding:1.5rem}'
                '</style><h1>Unveil</h1><p>Análise estática · relatório completo</p><pre>'
                + html.escape(serialized) + '</pre></html>\n')
    if format != 'text':
        raise ValueError('Unknown report format')
    lines = ['Unveil ' + report['tool']['version'],
             'Input: ' + report['input']['path'],
             'Type: ' + report['input']['type'],
             'SHA-256: ' + report['input']['sha256'],
             'Status: ' + report['status']]
    for finding in report['findings']:
        lines.append('[%s] %s (confidence=%s): %s' % (
            finding['severity'], finding['id'], finding['confidence'], '; '.join(finding['evidence'])))
    lines.append('Details:\n' + serialized)
    return '\n'.join(lines)


def write_report(path, report, format='json', inputs=()):
    protect_output(path, inputs)
    content = render(report, format)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
