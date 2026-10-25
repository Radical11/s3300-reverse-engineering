"""Index retained functions in separate firmware executable namespaces.

Reuses the authenticated application index; separately byte-checks the updater,
tiny loader and primary ELF dossiers. Packed carriers remain inventory-only.
All generated pseudocode/databases stay in ignored local derived output.
"""
import argparse
from contextlib import closing
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sqlite3

from elftools.elf.elffile import ELFFile
from map_recovery_transport import ElfBytes
from workspace_functions import load_analysis

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'
ANALYSIS = '15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040'
INDEX_KIND = 'artifact-functions-v1'
CARRIERS = ((0x200, 'Updater · original ELF'), (0x1006c0, 'Tiny loader · MIPS16'),
            (0x1026c0, 'Primary · original ELF'), (0x2202c0, 'Packed carrier 002202c0'),
            (0x3bd9a8, 'Packed carrier 003bd9a8'), (0x5c2b78, 'Packed carrier 005c2b78'))
SCHEMA = '''CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE images(id TEXT PRIMARY KEY,label TEXT,input_sha256 TEXT,language TEXT,entry INTEGER,flags INTEGER,function_count INTEGER,status TEXT,scope TEXT);
CREATE TABLE functions(image TEXT,address INTEGER,name TEXT,pseudocode TEXT,decompiled INTEGER,warning TEXT,signature TEXT,ranges_json TEXT,source_file TEXT,PRIMARY KEY(image,address));
CREATE TABLE edges(image TEXT,source INTEGER,target TEXT,type TEXT);
CREATE TABLE references_from(image TEXT,site INTEGER,target TEXT,type TEXT,function_address INTEGER);
CREATE TABLE indirect_transfers(image TEXT,site INTEGER,function_address INTEGER,instruction TEXT,resolved_targets_json TEXT);
CREATE INDEX refs_target ON references_from(image,target);
CREATE INDEX edges_target ON edges(image,target);
CREATE INDEX edges_source ON edges(image,source);
CREATE INDEX indirect_function ON indirect_transfers(image,function_address);'''


def sha(body): return hashlib.sha256(body).hexdigest()


def readonly(database):
    connection = sqlite3.connect(Path(database).resolve(strict=True).as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    return closing(connection)


def authenticate_index(database, *, expected_kind=None):
    """Check exact file digest and both source identities before opening data."""
    database = Path(database).resolve(strict=True)
    manifest_path = database.parent/'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (manifest.get('source_sha256') != BASELINE or manifest.get('analysis_sha256') != ANALYSIS or
            manifest.get('database_sha256') != sha(database.read_bytes())):
        raise ValueError('Index source identity or database hash differs')
    if expected_kind is not None and manifest.get('index_kind') != expected_kind:
        raise ValueError('Incompatible index kind; choose the artifact namespace index')
    with readonly(database) as connection:
        metadata = dict(connection.execute('SELECT key,value FROM metadata'))
        if metadata.get('source_sha256') != BASELINE or metadata.get('analysis_sha256') != ANALYSIS:
            raise ValueError('Index database source metadata differs')
        if expected_kind is not None and metadata.get('index_kind') != expected_kind:
            raise ValueError('Index database namespace metadata differs')
        if connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Index integrity check failed')
    return manifest


def authenticate_imported_instructions(mapping, dossier):
    """Reject every unbacked or changed instruction, including failed functions."""
    instructions = dossier.get('instructions', [])
    if not instructions: raise ValueError('Native function has no imported instructions')
    for row in instructions:
        body = bytes.fromhex(row['bytes'])
        if not body or len(body) > 16: raise ValueError('Invalid imported instruction extent')
        address = int(row['address'], 16)
        if mapping.read(address, len(body)) != body:
            raise ValueError(f'Native imported instruction differs at{address:#x}')
    return len(instructions)


def selected_dossier(path):
    initial = json.loads(path.read_text(encoding='utf-8'))
    replacement = path.parent.parent/'retry-functions'/path.name
    if replacement.is_file():
        retry = json.loads(replacement.read_text(encoding='utf-8'))
        if retry.get('initial_decompilation') != initial:
            raise ValueError('Retry overlay is not bound to the retained initial failure')
        if retry.get('decompilation_completed'): return retry, True
    return initial, False


def local_path(path):
    try: return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError: return str(path.resolve())


def insert_dossier(connection, image, path, mapping, *, allow_retry=True):
    row, recovered = selected_dossier(path) if allow_retry else (json.loads(path.read_text(encoding='utf-8')), False)
    address = int(row['address'], 16)
    if path.stem != f'{address:08x}': raise ValueError('Native dossier entry/path differs')
    checked = authenticate_imported_instructions(mapping, row)
    connection.execute('INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)',
        (image, address, row['name'], row.get('pseudocode'), bool(row.get('decompilation_completed')),
         row.get('decompiler_message'), row.get('signature_inferred'), json.dumps(row['ranges']), local_path(path)))
    refs = row.get('references', [])
    skipped = 0
    for reference in refs:
        if re.fullmatch(r'[0-9a-fA-F]{1,8}', reference['from']):
            connection.execute('INSERT INTO references_from VALUES (?,?,?,?,?)',
                (image, int(reference['from'],16), reference['to'], reference['type'], address))
        else: skipped += 1
    for target in row.get('callees', []):
        connection.execute('INSERT INTO edges VALUES (?,?,?,?)', (image, address, target, 'resolved_static_call'))
    for instruction in row['instructions']:
        operation = instruction['text'].lstrip('_').split(None, 1)
        if (operation and operation[0].lower() in ('jalr','jr','jalrc','jrc') and
                not (len(operation) > 1 and operation[1].strip() in ('ra','$ra'))):
            targets = [reference['to'] for reference in refs if reference['from'] == instruction['address']
                       and any(kind in reference['type'].upper() for kind in ('CALL','JUMP'))]
            connection.execute('INSERT INTO indirect_transfers VALUES (?,?,?,?,?)',
                (image, int(instruction['address'],16), address, instruction['text'], json.dumps(targets)))
    return {'instructions_checked': checked, 'recovered': recovered,
            'decompilation_failed': not row.get('decompilation_completed',False),
            'nondefault_reference_sites_omitted': skipped}


def authenticate_writer_focus(workspace, source, native, focus):
    """Authenticate only the caller-seeded application writer export.

    Its original application project and base index remain unchanged. A retry
    file beside the focused dossier is deliberately not an eligible overlay.
    """
    import map_application_write_scope as verifier
    focus = Path(focus).resolve()
    report = verifier.build_report(workspace, source, native, focus)
    evidence = report['focused_analysis']
    records = report['native_corroboration']['focused_writer']['records']
    if (report.get('source_sha256') != BASELINE or report.get('analysis_sha256') != ANALYSIS
            or report.get('target_executed') is not False or report.get('camera_commands_issued') is not False
            or evidence.get('entry') != 0x803d73dc or evidence.get('existing_application_project_modified') is not False
            or len(records) != 1 or records[0].get('address') != 0x803d73dc
            or not evidence.get('boundary_scope') or not evidence.get('inference_warning')):
        raise ValueError('Focused application writer identity or scope differs')
    path = focus/'application/functions/803d73dc.json'
    if sha(path.read_bytes()) != records[0]['dossier_sha256']:
        raise ValueError('Focused application writer changed after authentication')
    return path, {'image': 'application', 'entry': 0x803d73dc, 'added_functions': 1,
        'directory': local_path(focus), 'dossier_sha256': records[0]['dossier_sha256'],
        'provenance_sha256': evidence['provenance_sha256'],
        'instructions_byte_checked': records[0]['instructions_checked'],
        'verification_report_sha256': sha(json.dumps(report,sort_keys=True,separators=(',',':')).encode('utf-8')),
        'verifier_sha256': sha(Path(verifier.__file__).read_bytes()),
        'native_tool_versions': evidence['native_tool_versions'], 'exporter_hashes': evidence['exporter_hashes'],
        'caller_seeded_boundary': True, 'authenticated_unwind_boundary': False,
        'boundary_scope': evidence['boundary_scope'], 'inference_warning': evidence['inference_warning'],
        'base_application_index_modified': False, 'target_executed': False}


def insert_writer_focus(connection, path, overlay, mapping):
    """Insert the authenticated single addition, never replace base entries."""
    address = 0x803d73dc
    if (overlay.get('entry') != address or overlay.get('image') != 'application'
            or path.name != '803d73dc.json' or sha(path.read_bytes()) != overlay['dossier_sha256']):
        raise ValueError('Focused application writer dossier identity differs')
    if connection.execute('SELECT 1 FROM functions WHERE image=? AND address=?',('application',address)).fetchone():
        raise ValueError('Focused application writer already exists in the copied base index')
    checked = insert_dossier(connection,'application',path,mapping,allow_retry=False)
    if checked['instructions_checked'] != overlay['instructions_byte_checked']:
        raise ValueError('Focused application writer instruction coverage differs')
    warning = connection.execute('SELECT warning FROM functions WHERE image=? AND address=?',('application',address)).fetchone()[0]
    warning = '\n'.join(value for value in (warning,overlay['boundary_scope'],overlay['inference_warning']) if value)
    connection.execute('UPDATE functions SET warning=? WHERE image=? AND address=?',(warning,'application',address))


def build(native, application_index, workspace, output, source=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin', *, application_writer_focus=None):
    native, workspace, output = map(lambda p: Path(p).resolve(), (native, workspace, output))
    source = Path(source).resolve(); original = source.read_bytes()
    if sha(original) != BASELINE: raise ValueError('Original firmware source identity differs')
    if output.exists() or not output.is_relative_to((ROOT/'derived').resolve()):
        raise ValueError('Artifact index must be a new local directory under derived/')
    manifest, analysis = load_analysis(workspace)
    if sha(analysis) != ANALYSIS or manifest.get('source_sha256') != BASELINE:
        raise ValueError('Decoded application identity differs')
    profile_path = native/'profile.json'; profile = json.loads(profile_path.read_text(encoding='utf-8'))
    if profile.get('source_sha256') != BASELINE or profile.get('analysis_sha256') != ANALYSIS:
        raise ValueError('Retained native analysis profile differs')
    application_index = Path(application_index).resolve()
    if application_index.is_dir(): application_index /= 'native.sqlite'
    app_manifest = authenticate_index(application_index)
    if app_manifest.get('index_kind') is not None:
        raise ValueError('Application reuse input must be the single application index, not another artifact index')
    # The retained app index already records full byte comparison and successful
    # retry overlays. Reuse it only after exact file+SQLite metadata checks.
    if not app_manifest.get('instructions_byte_checked') or app_manifest.get('instructions_without_original_file_backing') != 0:
        raise ValueError('Application index lacks complete original-byte verification')
    app_image = json.loads((native/'application/image.json').read_text(encoding='utf-8'))
    if app_image.get('executable_sha256') != ANALYSIS: raise ValueError('Application native image differs')
    if app_image.get('function_inventory_count') != app_manifest['counts']['functions']:
        raise ValueError('Application index is stale relative to the retained native inventory')
    app_elf = ELFFile(BytesIO(analysis))
    writer_path = writer_overlay = None
    if application_writer_focus is not None:
        writer_path, writer_overlay = authenticate_writer_focus(workspace,source,native,application_writer_focus)
    originals = []
    for offset, label in CARRIERS:
        image = f'image-{offset:08x}'; path = workspace/'elf-original'/(image+'.elf'); raw = path.read_bytes()
        if original[offset:offset+len(raw)] != raw: raise ValueError('Original ELF differs from source carrier slice')
        elf = ELFFile(BytesIO(raw)); info = json.loads((native/image/'image.json').read_text(encoding='utf-8'))
        summary = json.loads((native/image/'verified-summary.json').read_text(encoding='utf-8'))
        if (info.get('executable_sha256') != sha(raw) or summary.get('input_sha256') != sha(raw)
                or info.get('language') != 'MIPS:LE:32:default' or summary.get('language') != info.get('language') or not summary.get('source_unchanged')
                or not summary.get('all_discovered_functions_exported')):
            raise ValueError('Separate native export identity, architecture or completeness differs')
        dossiers = sorted((native/image/'functions').glob('*.json'))
        if len(dossiers) != info.get('function_inventory_count') or len(dossiers) != summary.get('discovered_functions'):
            raise ValueError('Separate native function inventory differs')
        packed = offset >= 0x2202c0
        if packed and (dossiers or 'inventory only' not in summary.get('representation','')):
            raise ValueError('Packed carrier must remain inventory-only without functions')
        originals.append((image, label, raw, elf, info, dossiers, packed))
    output.mkdir(parents=True)
    (output/'INCOMPLETE.json').write_text(json.dumps({'source_sha256':BASELINE,'state':'building; no manifest means not queryable'})+'\n')
    database = output/'native.sqlite'; image_records = []; corroboration = []
    with closing(sqlite3.connect(database, uri=True)) as connection:
        connection.executescript(SCHEMA)
        connection.executemany('INSERT INTO metadata VALUES (?,?)', [('source_sha256',BASELINE),
            ('analysis_sha256',ANALYSIS),('index_kind',INDEX_KIND),('evidence_class','Direct Ghidra static analysis; separate executable namespaces')])
        connection.execute('ATTACH DATABASE ? AS app', (application_index.as_uri()+'?mode=ro',))
        connection.execute("INSERT INTO functions SELECT 'application',address,name,pseudocode,decompiled,warning,signature,ranges_json,source_file FROM app.functions")
        connection.execute("INSERT INTO edges SELECT 'application',source,target,type FROM app.edges")
        connection.execute("INSERT INTO references_from SELECT 'application',site,target,type,function_address FROM app.references_from")
        connection.execute("INSERT INTO indirect_transfers SELECT 'application',site,function_address,instruction,resolved_targets_json FROM app.indirect_transfers")
        count = connection.execute("SELECT count(*) FROM functions WHERE image='application'").fetchone()[0]
        if count != app_manifest['counts']['functions']: raise ValueError('Application copied row count differs')
        app_scope = 'Decoded synthetic analysis ELF; inferred functions/types, not an installable image or recovered original source.'
        if writer_overlay is not None:
            insert_writer_focus(connection,writer_path,writer_overlay,ElfBytes(analysis))
            count = connection.execute("SELECT count(*) FROM functions WHERE image='application'").fetchone()[0]
            if count != app_manifest['counts']['functions'] + 1:
                raise ValueError('Focused application writer must add exactly one function')
            app_scope += ' Includes one separately authenticated caller-seeded writer boundary; inferred types retain an explicit warning.'
        image_records.append(('application','Application · decoded analysis',ANALYSIS,app_image['language'],
            int(app_elf['e_entry']),int(app_elf['e_flags']),count,'indexed',
            app_scope))
        for image, label, raw, elf, info, dossiers, packed in originals:
            mapping = ElfBytes(raw); checked = failures = recovered = omitted = 0
            dossier_hashes = []
            for path in dossiers:
                record = insert_dossier(connection, image, path, mapping)
                checked += record['instructions_checked']; failures += record['decompilation_failed']
                recovered += record['recovered']; omitted += record['nondefault_reference_sites_omitted']
                dossier_hashes.append((path.name, sha(path.read_bytes())))
            scope = ('Packed carrier representation; inventory only. Decoded executable functions live in the application namespace.' if packed else
                'Original executable carrier; imported instruction bytes checked against this ELF only. Address collisions with other images remain separate.')
            if image == 'image-001006c0': scope += ' MIPS16 loader: odd ELF entry/mode retained; function addresses use Ghidra canonical entries.'
            image_records.append((image,label,sha(raw),info['language'],int(elf['e_entry']),int(elf['e_flags']),len(dossiers),
                'inventory-only' if packed else 'indexed',scope))
            corroboration.append({'image':image,'input_sha256':sha(raw),'functions':len(dossiers),'instructions_byte_checked':checked,
                'decompilation_failures':failures,'retry_overlays_used':recovered,'nondefault_reference_sites_omitted':omitted,
                'dossier_hashes_digest':sha(json.dumps(dossier_hashes,separators=(',',':')).encode('utf-8'))})
        connection.executemany('INSERT INTO images VALUES (?,?,?,?,?,?,?,?,?)', image_records)
        connection.commit()
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Artifact database integrity failed')
        counts = {table:connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
            for table in ('images','functions','edges','references_from','indirect_transfers')}
    if sha(source.read_bytes()) != BASELINE: raise ValueError('Original source changed during indexing')
    if sha(application_index.read_bytes()) != app_manifest['database_sha256']: raise ValueError('Application index changed during reuse')
    if writer_overlay is not None:
        if (sha(writer_path.read_bytes()) != writer_overlay['dossier_sha256']
                or sha((writer_path.parents[2]/'provenance.json').read_bytes()) != writer_overlay['provenance_sha256']):
            raise ValueError('Focused application writer input changed during indexing')
    report = {'schema_version':1,'index_kind':INDEX_KIND,'source_sha256':BASELINE,'analysis_sha256':ANALYSIS,
        'database_sha256':sha(database.read_bytes()),'counts':counts,
        'images':[dict(zip(('id','label','input_sha256','language','entry','flags','function_count','status','scope'), row)) for row in image_records],
        'application_index_reused':{'database_sha256':app_manifest['database_sha256'],
            'manifest_sha256':sha((application_index.parent/'manifest.json').read_bytes()),
            'instructions_byte_checked':app_manifest['instructions_byte_checked'],
            'initial_decompilation_failures':app_manifest.get('initial_decompilation_failures'),
            'focused_retry_successes':app_manifest.get('focused_retry_successes'),
            'remaining_decompilation_failures':app_manifest.get('decompilation_failures')},
        'native_profile_sha256':sha(profile_path.read_bytes()),'separate_image_corroboration':corroboration,
        'native_tool_versions':profile.get('tools',{}).get('versions',{}),
        'builder_sha256':sha(Path(__file__).read_bytes()),
        'target_executed':False,'camera_accessed':False,'limitations':[
            'Namespaces prevent address collisions; no claim that these executables are simultaneously installed at their ELF addresses.',
            'Imported-byte equality is not proof of inferred signatures, reachable branches or runtime safety.',
            'Packed carriers have no executable function indexing; no disassembly of compressed payloads is fabricated.',
            'MIPS16 instruction bytes and original flags are retained without a second decoder or hardware execution.']}
    if writer_overlay is not None:
        report['application_writer_overlay'] = writer_overlay
    with (output/'manifest.json').open('x',encoding='utf-8') as handle: json.dump(report,handle,indent=2); handle.write('\n')
    (output/'INCOMPLETE.json').unlink()
    return report


class ArtifactIndex:
    """Authenticate once at startup; reject database changes during a session."""
    def __init__(self, database):
        self.database = Path(database).resolve(strict=True)
        self.manifest = authenticate_index(self.database, expected_kind=INDEX_KIND)
        stat = self.database.stat(); self.stamp = (stat.st_size,stat.st_mtime_ns)

    def connect(self):
        stat = self.database.stat()
        if (stat.st_size,stat.st_mtime_ns) != self.stamp: raise ValueError('Artifact index changed during the session; authenticate it again')
        return readonly(self.database)

    def images(self):
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM images ORDER BY CASE WHEN id='application' THEN 0 ELSE 1 END,id")]

    def query(self, image='application', address=None, term='', limit=30, offset=0):
        if not isinstance(image,str) or not re.fullmatch(r'[a-z0-9-]{1,64}',image): raise ValueError('Invalid executable namespace')
        if type(limit) is not int or not 1 <= limit <= 1000 or type(offset) is not int or not 0 <= offset <= 1000000:
            raise ValueError('Use limit1..1000 and bounded nonnegative offset')
        if not isinstance(term,str) or len(term)>160: raise ValueError('Search term must be at most160 characters')
        if address is not None and (type(address) is not int or not 0 <= address <= 0xffffffff): raise ValueError('Expected unsigned32-bit function address')
        with self.connect() as connection:
            info = connection.execute('SELECT * FROM images WHERE id=?',(image,)).fetchone()
            if info is None: raise ValueError('Unknown executable namespace')
            result = {'image':image,'image_info':dict(info)}
            if address is not None:
                row = connection.execute('SELECT * FROM functions WHERE image=? AND address=?',(image,address)).fetchone()
                groups = {}
                for name,table,where,args in (
                    ('incoming_calls','edges','target=?',(f'{address:08x}',)),
                    ('outgoing_calls','edges','source=?',(address,)),
                    ('indirect_transfers','indirect_transfers','function_address=?',(address,)),
                    ('references_to_entry','references_from','target=?',(f'{address:08x}',))):
                    groups[name] = [dict(item) for item in connection.execute(f'SELECT * FROM {table} WHERE image=? AND {where} LIMIT 201',(image,*args))]
                return {**result,'function':dict(row) if row else None,
                    **{name:items[:200] for name,items in groups.items()},
                    'truncated_groups':[name for name,items in groups.items() if len(items)>200],
                    'scope':'Exact canonical function entry within the selected executable only; static references and inferred pseudocode.'}
            pattern = '%'+term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
            rows = connection.execute("SELECT image,address,name,decompiled,warning,signature,source_file FROM functions WHERE image=? AND(name LIKE ? ESCAPE '\\' OR pseudocode LIKE ? ESCAPE '\\') ORDER BY address LIMIT ? OFFSET ?",
                (image,pattern,pattern,limit+1,offset)).fetchall()
            return {**result,'functions':[dict(row) for row in rows[:limit]],'offset':offset,
                'next_offset':offset+limit if len(rows)>limit else None,
                'scope':'Selected executable namespace only; inventory-only images intentionally contain no functions.'}


def query(database,image='application',address=None,term='',limit=30,offset=0):
    return ArtifactIndex(database).query(image,address,term,limit,offset)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',nargs='?',type=Path)
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--application-index',type=Path,default=ROOT/'derived/native-index-final/native.sqlite')
    parser.add_argument('--application-writer-focus',type=Path,help='Optional authenticated caller-seeded803d73dc focused export; never replaces a base function')
    parser.add_argument('--workspace',type=Path,default=ROOT/'derived/unpacked-v1.1-indexed')
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--query',type=Path)
    parser.add_argument('--image',default='application')
    parser.add_argument('--address',type=lambda value:int(value,0))
    parser.add_argument('--search',default='')
    parser.add_argument('--limit',type=int,default=30)
    args = parser.parse_args()
    if args.query: result=query(args.query,args.image,args.address,args.search,args.limit)
    elif args.output:
        report=build(args.native,args.application_index,args.workspace,args.output,args.source,application_writer_focus=args.application_writer_focus)
        result={'output':str(args.output.resolve()),'counts':report['counts'],'images':report['images'],'camera_accessed':False}
    else: parser.error('Supply an output directory or --query DATABASE')
    print(json.dumps(result,indent=2))


if __name__ == '__main__': main()
