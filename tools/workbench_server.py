"""Read-only localhost browser for retained S3300 analysis and contracts.

No camera libraries, subprocesses, patches or update operations are exposed.
Native vendor-derived pseudocode stays in the local retained database.
"""
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import parse_qs, urlsplit

from development_platform import readiness, interface_catalog

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'
ANALYSIS = '15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040'
ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
          '/style.css': ('style.css', 'text/css; charset=utf-8')}


class Workbench:
    def __init__(self, root=ROOT, database=None):
        self.root = Path(root).resolve()
        current_database = self.root / 'derived/artifact-function-index-current/native.sqlite'
        artifact_database = current_database if current_database.is_file() else self.root / 'derived/artifact-function-index-v1.1/native.sqlite'
        default_database = artifact_database if artifact_database.is_file() else self.root / 'derived/native-index-final/native.sqlite'
        self.database = Path(database or default_database).resolve()
        self.index = None
        self.database_stamp = None
        self.artifacts = None
        if self.database.is_file():
            manifest = self.database.parent / 'manifest.json'
            self.index = json.loads(manifest.read_text(encoding='utf-8'))
            if (self.index.get('source_sha256') != SOURCE or self.index.get('analysis_sha256') != ANALYSIS or
                    self.index.get('database_sha256') != hashlib.sha256(self.database.read_bytes()).hexdigest()):
                raise ValueError('Native index identity or database hash differs; rebuild the index')
            stat = self.database.stat()
            self.database_stamp = (stat.st_size, stat.st_mtime_ns)
            if self.index.get('index_kind') == 'artifact-functions-v1':
                from index_artifact_functions import ArtifactIndex
                self.artifacts = ArtifactIndex(self.database)
            with self.connect() as db:
                metadata = dict(db.execute('SELECT key,value FROM metadata'))
                if metadata.get('source_sha256') != SOURCE or metadata.get('analysis_sha256') != ANALYSIS:
                    raise ValueError('Native database metadata differs')
        self.reports = {}
        for path in sorted((self.root / 'evidence').glob('*.json')):
            if path.is_symlink(): continue
            body = json.loads(path.read_text(encoding='utf-8'))
            if (isinstance(body, dict) and body.get('source_sha256') == SOURCE and
                    ('contracts' in body or 'image_namespaces' in body)):
                self.reports[path.stem] = path

    def connect(self):
        if self.index is None: raise ValueError('Retained native index is unavailable; use native-index first')
        stat = self.database.stat()
        if (stat.st_size, stat.st_mtime_ns) != self.database_stamp:
            raise ValueError('Native index changed while browsing; restart after authenticating the new index')
        db = sqlite3.connect(self.database.resolve(strict=True).as_uri() + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        # Bounded SQLite VM work; no unbounded regular expressions or SQL input.
        budget = [0]
        def progress():
            budget[0] += 1
            return budget[0] > 10000
        db.set_progress_handler(progress, 1000)
        return closing(db)

    def status(self):
        current = readiness(self.root)
        return {'source_sha256': SOURCE, 'resource_ready': current['resource_ready'],
            'code_ready': current['code_ready'], 'gates': current['gates'],
            'feature_dependencies': current['feature_dependencies'], 'native_available': self.index is not None,
            'native_coverage': self.index, 'research_reports': sorted(self.reports),
            'images': self.images(),
            'backup_coverage': current['backup_coverage'],
            'camera_operations': False,
            'scope': 'Direct Ghidra static analysis and source-bound research; inferred functions and types are not verified camera APIs.'}

    def images(self):
        if self.artifacts is not None: return self.artifacts.images()
        return [{'id': 'application', 'label': 'Application · decoded analysis',
                 'function_count': (self.index or {}).get('counts', {}).get('functions'),
                 'status': 'indexed' if self.index else 'unavailable',
                 'scope': 'Legacy application-only index; artifact-index adds separate executable namespaces.'}]

    def functions(self, term, limit, offset, image='application'):
        if len(term) > 160 or not 1 <= limit <= 100 or not 0 <= offset <= 1000000:
            raise ValueError('Use a search up to160 characters, limit1..100 and bounded nonnegative offset')
        if self.artifacts is not None:
            return self.artifacts.query(image=image, term=term, limit=limit, offset=offset)
        if image != 'application': raise ValueError('This index only contains the application namespace')
        pattern = '%' + term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        with self.connect() as db:
            rows = db.execute("SELECT address,name,decompiled,warning,signature FROM functions WHERE name LIKE ? ESCAPE '\\' OR pseudocode LIKE ? ESCAPE '\\' ORDER BY address LIMIT ? OFFSET ?",
                              (pattern, pattern, limit + 1, offset)).fetchall()
        return {'functions': [dict(row) for row in rows[:limit]], 'offset': offset,
                'next_offset': offset + limit if len(rows) > limit else None,
                'scope': 'Searches retained names and pseudocode; result order is by address, not confidence.'}

    def function(self, address, image='application'):
        if not 0 <= address <= 0xffffffff: raise ValueError('Use an unsigned32-bit address')
        if self.artifacts is not None:
            result = self.artifacts.query(image=image, address=address)
            if result['function'] is not None:
                function = result['function']; text = function.get('pseudocode') or ''
                function['pseudocode'] = text[:200000]; function['pseudocode_truncated'] = len(text) > 200000
            result['known_contracts'] = self.contracts_for(image,address)
            return result
        if image != 'application': raise ValueError('This index only contains the application namespace')
        with self.connect() as db:
            row = db.execute('SELECT * FROM functions WHERE address=?', (address,)).fetchone()
            if row is None: return {'function': None, 'scope': 'No native function entry at that exact address; this does not prove absence of code.'}
            function = dict(row)
            text = function.get('pseudocode') or ''
            function['pseudocode'] = text[:200000]
            function['pseudocode_truncated'] = len(text) > 200000
            target = f'{address:08x}'
            incoming = [dict(r) for r in db.execute('SELECT source,target,type FROM edges WHERE target=? ORDER BY source LIMIT 201', (target,))]
            outgoing = [dict(r) for r in db.execute('SELECT source,target,type FROM edges WHERE source=? ORDER BY target LIMIT 201', (address,))]
            indirect = [dict(r) for r in db.execute('SELECT * FROM indirect_transfers WHERE function_address=? ORDER BY site LIMIT 201', (address,))]
            references = [dict(r) for r in db.execute('SELECT * FROM references_from WHERE target=? ORDER BY site LIMIT 201', (target,))]
        groups = {'incoming_calls': incoming, 'outgoing_calls': outgoing,
                  'indirect_transfers': indirect, 'references_to_entry': references}
        return {'function': function, **{name: rows[:200] for name, rows in groups.items()},
                'known_contracts': self.contracts_for(image,address),
                'truncated_groups': [name for name, rows in groups.items() if len(rows) > 200],
                'scope': 'Static indexed transfers; unresolved indirect calls remain research. Exact-entry lookup only.'}

    def contracts_for(self, image, address):
        return [item for item in self.interfaces()['interfaces']
                if item.get('image_namespace', 'application') == image
                and f'0x{address:08x}' in (item.get('address') or '').lower()]

    def interfaces(self, term=''):
        result = interface_catalog(term, root=self.root)
        if result.get('source_sha256') != SOURCE: raise ValueError('Interface catalog source identity differs')
        return result

    def limits(self, term=''):
        if len(term) > 160: raise ValueError('Search is too long')
        result = json.loads((self.root / 'hardware/s3300.json').read_text(encoding='utf-8'))
        if result.get('baseline_sha256') != SOURCE: raise ValueError('Hardware catalog source identity differs')
        if term:
            result['entries'] = [entry for entry in result['entries']
                                 if term.casefold() in json.dumps(entry).casefold()]
        return result

    def report(self, name):
        if name not in self.reports: raise ValueError('Unknown source-bound research report')
        path = self.reports[name]
        body = path.read_bytes()
        report = json.loads(body)
        if report.get('source_sha256') != SOURCE: raise ValueError('Research source identity changed')
        return {'name': name, 'sha256': hashlib.sha256(body).hexdigest(), 'report': report}


def handler_for(workbench):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'S3300LocalWorkbench'
        def log_message(self, *args): pass
        def respond(self, status, body, content_type='application/json; charset=utf-8'):
            if not isinstance(body, bytes): body = (json.dumps(body, ensure_ascii=True) + '\n').encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            port = self.server.server_address[1]
            host = self.headers.get('Host', '')
            if host not in (f'127.0.0.1:{port}', f'localhost:{port}'):
                return self.respond(403, {'error': 'Use the local workbench address'})
            origin = self.headers.get('Origin')
            if origin and origin != f'http://{host}':
                return self.respond(403, {'error': 'Cross-origin requests are not supported'})
            if len(self.path) > 4096: return self.respond(400, {'error': 'Request is too long'})
            parsed = urlsplit(self.path)
            try:
                params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
                if any(len(values) != 1 for values in params.values()): raise ValueError('Duplicate query parameter')
                def take(name, default=''): return params.get(name, [default])[0]
                if parsed.path in ASSETS:
                    if params: raise ValueError('Static assets take no query parameters')
                    name, kind = ASSETS[parsed.path]
                    return self.respond(200, (Path(__file__).parent / 'workbench' / name).read_bytes(), kind)
                if parsed.path == '/api/status' and not params:
                    result = workbench.status()
                elif parsed.path == '/api/interfaces' and set(params) <= {'q'}:
                    if len(take('q')) > 160: raise ValueError('Search is too long')
                    result = workbench.interfaces(take('q'))
                elif parsed.path == '/api/limits' and set(params) <= {'q'}:
                    result = workbench.limits(take('q'))
                elif parsed.path == '/api/functions' and set(params) <= {'q', 'limit', 'offset', 'image'}:
                    result = workbench.functions(take('q'), int(take('limit', '30')), int(take('offset', '0')),take('image','application'))
                elif parsed.path == '/api/function' and 'address' in params and set(params) <= {'address','image'}:
                    value = take('address')
                    if not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,8}', value): raise ValueError('Use a hexadecimal function address')
                    result = workbench.function(int(value, 16),take('image','application'))
                elif parsed.path == '/api/research' and not params:
                    result = {'reports': sorted(workbench.reports)}
                elif parsed.path == '/api/research' and set(params) == {'name'}:
                    result = workbench.report(take('name'))
                else: return self.respond(404, {'error': 'No such read-only view'})
                self.respond(200, result)
            except (ValueError, OSError, KeyError, sqlite3.Error) as error:
                self.respond(400, {'error': str(error)})
        def do_POST(self): self.respond(405, {'error': 'This workbench only serves read-only GET views'})
        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST
    return Handler


def serve(port=0, root=ROOT, database=None):
    if not 0 <= port <= 65535: raise ValueError('Port must be0..65535')
    workbench = Workbench(root, database)
    with ThreadingHTTPServer(('127.0.0.1', port), handler_for(workbench)) as server:
        print(json.dumps({'url': f'http://127.0.0.1:{server.server_address[1]}',
            'camera_operations': False, 'native_available': workbench.index is not None,
            'stop': 'PressCtrl+C in the terminal to close the local browser service'}), flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
