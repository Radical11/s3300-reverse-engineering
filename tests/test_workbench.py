"""Local browser data integrity, query bounds and read-only HTTP boundaries."""
from contextlib import contextmanager, closing
import hashlib
from http.server import ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from workbench_server import Workbench, handler_for, SOURCE, ANALYSIS


class WorkbenchTests(unittest.TestCase):
    def fixture(self, root):
        database = root / 'derived/native-index-final/native.sqlite'
        database.parent.mkdir(parents=True)
        with closing(sqlite3.connect(database)) as db:
            db.executescript('''CREATE TABLE metadata(key TEXT,value TEXT);
                CREATE TABLE functions(address INTEGER PRIMARY KEY,name TEXT,pseudocode TEXT,decompiled INTEGER,warning TEXT,signature TEXT,ranges_json TEXT,source_file TEXT);
                CREATE TABLE edges(source INTEGER,target TEXT,type TEXT);
                CREATE TABLE indirect_transfers(site INTEGER,function_address INTEGER,instruction TEXT,resolved_targets_json TEXT);
                CREATE TABLE references_from(site INTEGER,target TEXT,type TEXT,function_address INTEGER);''')
            db.executemany('INSERT INTO metadata VALUES (?,?)', [('source_sha256', SOURCE), ('analysis_sha256', ANALYSIS)])
            db.executemany('INSERT INTO functions VALUES (?,?,?,?,?,?,?,?)', [
                (0x80001000, 'percent%name', 'synthetic_alpha', 1, '', 'inferred', '[]', 'local-dossier.json'),
                (0x80002000, 'normal', 'synthetic_beta', 1, '', 'inferred', '[]', 'local-dossier.json'),
                (0x80003000, 'failed', '', 0, 'retained synthetic timeout', None, '[]', 'local-dossier.json')])
            db.execute('INSERT INTO edges VALUES (?,?,?)', (0x80001000, '80002000', 'resolved_static_call'))
            db.execute('INSERT INTO indirect_transfers VALUES (?,?,?,?)', (0x80002004, 0x80002000, 'jalr t9', '[]'))
            db.execute('INSERT INTO references_from VALUES (?,?,?,?)', (0x80001008, '80002000', 'UNCONDITIONAL_CALL', 0x80001000))
            db.commit()
        self.manifest(database)
        path = root / 'firmware/sdk/interfaces.json'; path.parent.mkdir(parents=True)
        path.write_text(json.dumps({'source_sha256': SOURCE, 'interfaces': [{'id': 'synthetic', 'camera_callable': False}]}))
        evidence = root / 'evidence'; evidence.mkdir()
        (evidence / 'reviewed.json').write_text(json.dumps({'source_sha256': SOURCE, 'contracts': [{'id': 'synthetic'}]}))
        (evidence / 'other-source.json').write_text(json.dumps({'source_sha256': 'other', 'contracts': []}))
        hardware = root / 'hardware/s3300.json'; hardware.parent.mkdir()
        hardware.write_text(json.dumps({'baseline_sha256': SOURCE, 'sources': {'fixture': {'path': 'notes/synthetic.md'}},
            'entries': [{'id': 'ram', 'kind': 'unknown', 'value': None, 'constraint': 'No measurement', 'sources': ['fixture']},
                        {'id': 'stock-size', 'kind': 'stock_limit', 'value': 16, 'constraint': 'Not a silicon ceiling', 'sources': ['fixture']}]}))
        return database

    def manifest(self, database):
        (database.parent / 'manifest.json').write_text(json.dumps({'source_sha256': SOURCE,
            'analysis_sha256': ANALYSIS, 'database_sha256': hashlib.sha256(database.read_bytes()).hexdigest()}))

    @contextmanager
    def server(self, workbench):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(workbench))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try: yield server.server_address[1]
        finally: server.shutdown(); server.server_close(); thread.join()

    def request(self, port, path, method='GET', headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse(); body = response.read(); status = response.status
        fields = dict(response.getheaders()); connection.close()
        return status, fields, body

    def test_database_hash_mismatch_rejected_before_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = self.fixture(root)
            with database.open('ab') as handle: handle.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'database hash differs'): Workbench(root)

    def test_analysis_metadata_must_match_even_when_manifest_hash_is_updated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = self.fixture(root)
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE metadata SET value='other' WHERE key='analysis_sha256'"); db.commit()
            self.manifest(database)
            with self.assertRaisesRegex(ValueError, 'metadata differs'): Workbench(root)

    def test_literal_search_pagination_and_retained_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); app = Workbench(root)
            self.assertEqual([r['name'] for r in app.functions('%', 10, 0)['functions']], ['percent%name'])
            first = app.functions('', 1, 0); self.assertEqual(first['next_offset'], 1)
            self.assertEqual(app.functions('', 1, first['next_offset'])['functions'][0]['name'], 'normal')
            self.assertEqual(app.function(0x80003000)['function']['warning'], 'retained synthetic timeout')
            self.assertIsNone(app.function(0x80002004)['function'])

    def test_reference_directions_and_unresolved_indirects_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); data = Workbench(root).function(0x80002000)
            self.assertEqual(data['incoming_calls'][0]['source'], 0x80001000)
            self.assertEqual(data['indirect_transfers'][0]['resolved_targets_json'], '[]')
            self.assertEqual(data['references_to_entry'][0]['site'], 0x80001008)

    def test_same_address_in_updater_is_not_an_application_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root)
            catalog = root / 'firmware/sdk/interfaces.json'
            catalog.write_text(json.dumps({'source_sha256': SOURCE, 'interfaces': [
                {'id': 'app', 'image_namespace': 'application', 'address': '0x80002000'},
                {'id': 'descriptor', 'image_namespace': 'application', 'address': None},
                {'id': 'updater', 'image_namespace': 'image-00000200', 'address': '0x80002000'}]}))
            self.assertEqual([item['id'] for item in Workbench(root).function(0x80002000)['known_contracts']], ['app'])

    def test_artifact_index_is_preferred_and_http_preserves_namespace(self):
        from index_artifact_functions import SCHEMA, INDEX_KIND
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root)
            database = root / 'derived/artifact-function-index-v1.1/native.sqlite'
            database.parent.mkdir()
            with closing(sqlite3.connect(database)) as db:
                db.executescript(SCHEMA)
                db.executemany('INSERT INTO metadata VALUES (?,?)', [('source_sha256', SOURCE), ('analysis_sha256', ANALYSIS), ('index_kind', INDEX_KIND)])
                for image in ('application', 'image-00000200'):
                    db.execute('INSERT INTO images VALUES (?,?,?,?,?,?,?,?,?)', (image, image, 'synthetic', 'MIPS:LE:32:default', 0x80001000, 0, 1, 'indexed', 'synthetic scope'))
                    db.execute('INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)', (image, 0x80001000, image+'-entry', 'synthetic', 1, '', '', '[]', 'synthetic'))
                db.commit()
            (database.parent/'manifest.json').write_text(json.dumps({'index_kind': INDEX_KIND, 'source_sha256': SOURCE,
                'analysis_sha256': ANALYSIS, 'database_sha256': hashlib.sha256(database.read_bytes()).hexdigest()}))
            app = Workbench(root)
            self.assertEqual(app.database, database)
            self.assertEqual(app.function(0x80001000)['function']['name'], 'application-entry')
            with self.server(app) as port:
                status, _, body = self.request(port, '/api/function?address=80001000&image=image-00000200')
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)['function']['name'], 'image-00000200-entry')
                self.assertEqual(self.request(port, '/api/functions?image=unknown')[0], 400)

    def test_search_and_address_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); app = Workbench(root)
            for args in (('x' * 161, 10, 0), ('', 101, 0), ('', 10, -1)):
                with self.assertRaises(ValueError): app.functions(*args)
            with self.assertRaises(ValueError): app.function(0x100000000)

    def test_database_changed_during_session_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = self.fixture(root); app = Workbench(root)
            with database.open('ab') as handle: handle.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed while browsing'): app.functions('', 10, 0)

    def test_absent_native_data_still_allows_honest_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = Workbench(Path(temporary)); report = app.status()
            self.assertFalse(report['native_available']); self.assertFalse(report['code_ready'])
            with self.assertRaisesRegex(ValueError, 'unavailable'): app.functions('Capture', 20, 0)

    def test_reports_are_allowlisted_and_source_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); app = Workbench(root)
            self.assertEqual(list(app.reports), ['reviewed'])
            with self.assertRaises(ValueError): app.report('../sources/firmware')
            (root / 'evidence/reviewed.json').write_text(json.dumps({'source_sha256': 'changed'}))
            with self.assertRaisesRegex(ValueError, 'identity changed'): app.report('reviewed')

    def test_hardware_unknowns_and_stock_constraints_survive_filtering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); app = Workbench(root)
            unknown = app.limits('ram')['entries'][0]
            self.assertIsNone(unknown['value']); self.assertEqual(unknown['kind'], 'unknown')
            self.assertEqual(app.limits('stock')['entries'][0]['constraint'], 'Not a silicon ceiling')
            path = root / 'hardware/s3300.json'; path.write_text(json.dumps({'baseline_sha256': 'wrong'}))
            with self.assertRaisesRegex(ValueError, 'source identity differs'): app.limits()

    def test_http_assets_and_api_are_local_and_get_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = self.fixture(root); original = database.read_bytes()
            with self.server(Workbench(root)) as port:
                status, headers, body = self.request(port, '/')
                self.assertEqual(status, 200); self.assertIn(b'S3300 workbench', body)
                self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
                self.assertNotIn('Access-Control-Allow-Origin', headers)
                for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                    self.assertEqual(self.request(port, '/api/function?address=80001000', method)[0], 405)
                self.assertEqual(self.request(port, '/api/functions?q=synthetic')[0], 200)
            self.assertEqual(database.read_bytes(), original)

    def test_http_rejects_rebinding_cross_origin_duplicate_and_private_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root)
            with self.server(Workbench(root)) as port:
                self.assertEqual(self.request(port, '/api/status', headers={'Host': 'untrusted.invalid'})[0], 403)
                self.assertEqual(self.request(port, '/api/status', headers={'Origin': 'https://untrusted.invalid'})[0], 403)
                self.assertEqual(self.request(port, '/api/functions?q=a&q=b')[0], 400)
                self.assertEqual(self.request(port, '/api/function?address=../../')[0], 400)
                self.assertEqual(self.request(port, '/%2e%2e/sources/firmware.bin')[0], 404)
                self.assertEqual(self.request(port, '/api/research?name=other-source')[0], 400)


if __name__ == '__main__': unittest.main()
