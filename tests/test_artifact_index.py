"""Executable namespaces, startup identity and stale import-byte rejection."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tools/vendor')]
from index_artifact_functions import (ArtifactIndex, SCHEMA, BASELINE, ANALYSIS,
    INDEX_KIND, sha, query, authenticate_imported_instructions, selected_dossier, build,
    authenticate_writer_focus, insert_writer_focus)


class ArtifactIndexTests(unittest.TestCase):
    def fixture(self, root):
        database = root/'native.sqlite'
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(SCHEMA)
            connection.executemany('INSERT INTO metadata VALUES (?,?)',
                [('source_sha256',BASELINE),('analysis_sha256',ANALYSIS),('index_kind',INDEX_KIND)])
            connection.executemany('INSERT INTO images VALUES (?,?,?,?,?,?,?,?,?)', [
                ('application','synthetic app','app-sha','MIPS:LE:32:default',0x80001000,0x70001001,2,'indexed','synthetic'),
                ('image-00000200','synthetic updater','boot-sha','MIPS:LE:32:default',0x80001000,0x70001001,1,'indexed','synthetic'),
                ('image-002202c0','packed','packed-sha','MIPS:LE:32:default',0x80001000,0x70001001,0,'inventory-only','packed bytes, no decoded functions')])
            connection.executemany('INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)', [
                ('application',0x80001000,'app_one','app-only percent%literal',1,'','inferred','[]','local-app.json'),
                ('application',0x80002000,'app_failed','',0,'retained failure',None,'[]','local-failed.json'),
                ('image-00000200',0x80001000,'updater_one','updater-only body',1,'','inferred','[]','local-updater.json')])
            connection.executemany('INSERT INTO edges VALUES (?,?,?,?)', [
                ('application',0x80002000,'80001000','app-call'),
                ('image-00000200',0x80003000,'80001000','updater-call')])
            connection.executemany('INSERT INTO references_from VALUES (?,?,?,?,?)', [
                ('application',0x80002004,'80001000','app-reference',0x80002000),
                ('image-00000200',0x80003004,'80001000','updater-reference',0x80003000)])
            connection.executemany('INSERT INTO indirect_transfers VALUES (?,?,?,?,?)', [
                ('application',0x80001004,0x80001000,'jalr t9','[]'),
                ('image-00000200',0x80001008,0x80001000,'jalr t8','[]')])
            connection.commit()
        self.manifest(database)
        return database

    def manifest(self, database, source=BASELINE, kind=INDEX_KIND):
        (database.parent/'manifest.json').write_text(json.dumps({'schema_version':1,'index_kind':kind,
            'source_sha256':source,'analysis_sha256':ANALYSIS,'database_sha256':sha(database.read_bytes())}))

    def test_same_address_functions_and_every_reference_group_stay_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary)); index=ArtifactIndex(database)
            app=index.query('application',0x80001000)
            updater=index.query('image-00000200',0x80001000)
            self.assertEqual(app['function']['name'],'app_one')
            self.assertEqual(updater['function']['name'],'updater_one')
            self.assertEqual(app['incoming_calls'][0]['type'],'app-call')
            self.assertEqual(updater['incoming_calls'][0]['type'],'updater-call')
            self.assertEqual(app['references_to_entry'][0]['type'],'app-reference')
            self.assertEqual(updater['references_to_entry'][0]['type'],'updater-reference')
            self.assertEqual(app['indirect_transfers'][0]['instruction'],'jalr t9')
            self.assertEqual(updater['indirect_transfers'][0]['instruction'],'jalr t8')

    def test_search_does_not_leak_other_executable_and_percent_is_literal(self):
        with tempfile.TemporaryDirectory() as temporary:
            index=ArtifactIndex(self.fixture(Path(temporary)))
            self.assertEqual(index.query('application',term='updater')['functions'],[])
            self.assertEqual(index.query('image-00000200',term='app-only')['functions'],[])
            self.assertEqual(index.query(term='%')['functions'][0]['name'],'app_one')

    def test_inventory_only_image_remains_visible_with_no_fake_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            index=ArtifactIndex(self.fixture(Path(temporary)))
            result=index.query('image-002202c0')
            self.assertEqual(result['image_info']['status'],'inventory-only')
            self.assertEqual(result['functions'],[])
            self.assertIsNone(index.query('image-002202c0',0x80001000)['function'])
            self.assertEqual(index.images()[0]['id'],'application')

    def test_failed_function_and_search_pagination_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            index=ArtifactIndex(self.fixture(Path(temporary)))
            first=index.query(limit=1)
            self.assertEqual(first['next_offset'],1)
            last=index.query(limit=1,offset=1)
            self.assertIsNone(last['next_offset'])
            self.assertEqual(index.query(address=0x80002000)['function']['warning'],'retained failure')

    def test_unknown_namespace_and_unbounded_queries_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            index=ArtifactIndex(self.fixture(Path(temporary)))
            for image in ('../application',"application' OR1=1",'unknown'):
                with self.assertRaises(ValueError): index.query(image)
            for options in ({'limit':1001},{'offset':-1},{'term':'x'*161},{'address':-1}):
                with self.assertRaises(ValueError): index.query(**options)

    def test_startup_rejects_changed_database_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary))
            with database.open('ab') as handle: handle.write(b'changed')
            with self.assertRaisesRegex(ValueError,'database hash differs'): ArtifactIndex(database)

    def test_startup_rejects_wrong_manifest_source_and_kind(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary)); self.manifest(database,source='wrong')
            with self.assertRaisesRegex(ValueError,'source identity'): ArtifactIndex(database)
            self.manifest(database,kind='single-application')
            with self.assertRaisesRegex(ValueError,'index kind'): ArtifactIndex(database)

    def test_startup_metadata_rejection_even_with_recomputed_manifest_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary))
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("UPDATE metadata SET value='wrong' WHERE key='analysis_sha256'"); connection.commit()
            self.manifest(database)
            with self.assertRaisesRegex(ValueError,'source metadata'): ArtifactIndex(database)

    def test_changes_after_startup_are_rejected_and_queries_are_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary)); index=ArtifactIndex(database); original=database.read_bytes()
            query(database,address=0x80001000)
            self.assertEqual(database.read_bytes(),original)
            with database.open('ab') as handle: handle.write(b'changed')
            with self.assertRaisesRegex(ValueError,'changed during'): index.query()

    def test_missing_manifest_cannot_open_interrupted_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=self.fixture(Path(temporary)); (database.parent/'manifest.json').unlink()
            with self.assertRaises(FileNotFoundError): ArtifactIndex(database)

    def test_import_bytes_are_checked_with_image_specific_mapping_and_mips16_extent(self):
        class Mapping:
            def __init__(self,body): self.body=body
            def read(self,address,size): return self.body[:size]
        dossier={'instructions':[{'address':'81000400','bytes':'ba65'}]}
        self.assertEqual(authenticate_imported_instructions(Mapping(bytes.fromhex('ba65')),dossier),1)
        with self.assertRaisesRegex(ValueError,'instruction differs'):
            authenticate_imported_instructions(Mapping(bytes.fromhex('0000')),dossier)
        with self.assertRaisesRegex(ValueError,'no imported instructions'):
            authenticate_imported_instructions(Mapping(b''),{'instructions':[]})

    def test_retry_overlay_must_bind_the_exact_initial_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); path=root/'functions/80001000.json'; path.parent.mkdir()
            initial={'address':'80001000','decompilation_completed':False,'instructions':[]}
            path.write_text(json.dumps(initial)); retry=root/'retry-functions/80001000.json'; retry.parent.mkdir()
            retry.write_text(json.dumps({'initial_decompilation':initial,'decompilation_completed':True,'pseudocode':'synthetic retry'}))
            self.assertTrue(selected_dossier(path)[1])
            initial['name']='changed'; path.write_text(json.dumps(initial))
            with self.assertRaisesRegex(ValueError,'not bound'):
                selected_dossier(path)

    def test_wrong_firmware_rejected_without_creating_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); source=root/'wrong.bin'; source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'source identity'):
                build(root,root,root,root/'output',source)
            self.assertFalse((root/'output').exists())


class WriterFocusOverlayTests(unittest.TestCase):
    def fixture(self, root):
        focus=root/'focused'; path=focus/'application/functions/803d73dc.json'
        path.parent.mkdir(parents=True)
        body=bytes.fromhex('08002003')
        dossier={'address':'803d73dc','name':'synthetic_writer','decompilation_completed':True,
            'pseudocode':'synthetic writer body','decompiler_message':'retained original warning',
            'signature_inferred':'synthetic signature','ranges':[{'start':'803d73dc','end_inclusive':'803d73df'}],
            'instructions':[{'address':'803d73dc','bytes':body.hex(),'text':'jr t9'}],
            'references':[{'from':'803d73dc','to':'80001000','type':'COMPUTED_CALL'}],
            'callees':['80001000']}
        path.write_text(json.dumps(dossier),encoding='utf-8')
        provenance=focus/'provenance.json';provenance.write_text('synthetic provenance',encoding='utf-8')
        evidence={'entry':0x803d73dc,'existing_application_project_modified':False,
            'provenance_sha256':sha(provenance.read_bytes()),
            'boundary_scope':'Caller-seeded boundary, not an authenticated unwind range',
            'inference_warning':'Type propagation algorithm not settling; inferred types incomplete',
            'native_tool_versions':{'ghidra':'12.1.4','jdk':'21.0.9+10'},'exporter_hashes':{'synthetic':'digest'}}
        report={'source_sha256':BASELINE,'analysis_sha256':ANALYSIS,'target_executed':False,
            'camera_commands_issued':False,'focused_analysis':evidence,
            'native_corroboration':{'focused_writer':{'records':[{'address':0x803d73dc,
                'dossier_sha256':sha(path.read_bytes()),'instructions_checked':1}]}}}
        class Mapping:
            def read(self,address,size):
                if address!=0x803d73dc:raise ValueError('Unexpected synthetic address')
                return body[:size]
        return focus,path,report,Mapping()

    def authenticate(self,root,focus,report):
        with patch('map_application_write_scope.build_report',return_value=report) as verify:
            result=authenticate_writer_focus(root/'workspace',root/'source',root/'native',focus)
            verify.assert_called_once_with(root/'workspace',root/'source',root/'native',focus.resolve())
            return result

    def test_authenticated_single_overlay_preserves_boundary_type_warning_and_edges(self):
        with tempfile.TemporaryDirectory() as temporary,closing(sqlite3.connect(':memory:')) as connection:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            selected,overlay=self.authenticate(root,focus,report)
            connection.executescript(SCHEMA)
            # Same address in another executable must neither block nor merge.
            connection.execute('INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)',
                ('image-00000200',0x803d73dc,'other-image','synthetic',1,'',None,'[]','other.json'))
            insert_writer_focus(connection,selected,overlay,mapping)
            rows=connection.execute('SELECT image,name,warning FROM functions ORDER BY image').fetchall()
            self.assertEqual([row[0] for row in rows],['application','image-00000200'])
            warning=rows[0][2]
            self.assertIn('retained original warning',warning)
            self.assertIn('Caller-seeded',warning);self.assertIn('Type propagation',warning)
            self.assertEqual(connection.execute('SELECT count(*) FROM edges').fetchone()[0],1)
            self.assertEqual(connection.execute('SELECT count(*) FROM indirect_transfers').fetchone()[0],1)
            self.assertEqual(overlay['added_functions'],1)
            self.assertFalse(overlay['base_application_index_modified'])
            self.assertFalse(overlay['authenticated_unwind_boundary'])

    def test_focus_does_not_silently_select_adjacent_or_retry_dossiers(self):
        with tempfile.TemporaryDirectory() as temporary,closing(sqlite3.connect(':memory:')) as connection:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            retry=path.parent.parent/'retry-functions'/path.name;retry.parent.mkdir()
            retry.write_text(json.dumps({'decompilation_completed':True,'name':'unverified retry'}))
            (path.parent/'803d73e0.json').write_text('{}')
            selected,overlay=self.authenticate(root,focus,report)
            connection.executescript(SCHEMA);insert_writer_focus(connection,selected,overlay,mapping)
            self.assertEqual(connection.execute('SELECT name FROM functions').fetchall(),[('synthetic_writer',)])

    def test_existing_application_entry_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary,closing(sqlite3.connect(':memory:')) as connection:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            selected,overlay=self.authenticate(root,focus,report)
            connection.executescript(SCHEMA);insert_writer_focus(connection,selected,overlay,mapping)
            with self.assertRaisesRegex(ValueError,'already exists'):
                insert_writer_focus(connection,selected,overlay,mapping)
            self.assertEqual(connection.execute('SELECT count(*) FROM functions').fetchone()[0],1)

    def test_focused_authentication_failure_and_identity_mismatch_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            with patch('map_application_write_scope.build_report',side_effect=ValueError('bad provenance')):
                with self.assertRaisesRegex(ValueError,'bad provenance'):
                    authenticate_writer_focus(root,root,root,focus)
            report['focused_analysis']['entry']=0x803d73e0
            with patch('map_application_write_scope.build_report',return_value=report):
                with self.assertRaisesRegex(ValueError,'identity or scope'):
                    authenticate_writer_focus(root,root,root,focus)

    def test_changed_dossier_is_rejected_after_focused_authentication(self):
        with tempfile.TemporaryDirectory() as temporary,closing(sqlite3.connect(':memory:')) as connection:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            selected,overlay=self.authenticate(root,focus,report)
            dossier=json.loads(path.read_text());dossier['pseudocode']='changed';path.write_text(json.dumps(dossier))
            connection.executescript(SCHEMA)
            with self.assertRaisesRegex(ValueError,'identity differs'):
                insert_writer_focus(connection,selected,overlay,mapping)
            self.assertEqual(connection.execute('SELECT count(*) FROM functions').fetchone()[0],0)

    def test_added_bytes_are_rechecked_even_after_report_authentication(self):
        with tempfile.TemporaryDirectory() as temporary,closing(sqlite3.connect(':memory:')) as connection:
            root=Path(temporary);focus,path,report,mapping=self.fixture(root)
            selected,overlay=self.authenticate(root,focus,report)
            class ChangedMapping:
                def read(self,address,size):return b'\0'*size
            connection.executescript(SCHEMA)
            with self.assertRaisesRegex(ValueError,'instruction differs'):
                insert_writer_focus(connection,selected,overlay,ChangedMapping())
            self.assertEqual(connection.execute('SELECT count(*) FROM functions').fetchone()[0],0)


if __name__ == '__main__': unittest.main()
