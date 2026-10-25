"""Recheck source-bound research maps using retained native analysis."""
import importlib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOPICS = {'saved-jpeg': ('map_saved_jpeg_path', ''),
          'cache-dma': ('map_cache_dma_contracts', 'application'),
          'reset-recovery': ('map_reset_recovery', ''),
          'ptp-vendor': ('map_ptp_vendor_contracts', 'application'),
          'usb-entry': ('map_usb_entry_contracts', 'application'),
          'shutter-route': ('map_shutter_route', 'application'),
          'shutter-input': ('map_shutter_input', 'application'),
          'pixel-layout': ('map_pixel_layout', ''),
          'menu-lifecycle': ('map_menu_lifecycle', ''),
          'update-write-scope': ('map_update_write_scope', ''),
          'backup-scope': ('map_backup_scope', ''),
          'backup-usb': ('map_backup_usb_contracts', 'application'),
          'updater-handoff': ('map_updater_handoff', ''),
          'application-write-scope': ('map_application_write_scope', '')}
SEPARATE_IMAGE_TOPICS = frozenset(('reset-recovery', 'update-write-scope'))


def provenance(topic, report, root):
    """Bind reused native analysis to its versions/scripts and this verifier."""
    path = root / 'derived/native-analysis-complete/profile.json'
    profile = json.loads(path.read_text(encoding='utf-8'))
    if (profile.get('source_sha256') != report['source_sha256'] or
            (topic not in SEPARATE_IMAGE_TOPICS and profile.get('analysis_sha256') != report.get('analysis_sha256')) or
            profile.get('tools', {}).get('versions') != {'ghidra': '12.1.4', 'jdk': '21.0.9+10'}):
        raise ValueError('Retained native analysis profile is incompatible')
    for name, expected in profile['scripts'].items():
        script = (root / 'tools/ghidra' / name).resolve()
        if not script.is_relative_to((root / 'tools/ghidra').resolve()) or hashlib.sha256(script.read_bytes()).hexdigest() != expected:
            raise ValueError('Retained native analysis exporter script differs')
    names = {TOPICS[topic][0] + '.py', 'research_contracts.py',
        'map_development_contracts.py', 'map_development_interfaces.py',
        'map_recovery_transport.py', 'map_capture_buffers.py', 'workspace_functions.py'}
    if topic == 'ptp-vendor': names.update(('verify_sdk_emulation.py', 'setup_sdk_toolchain.py'))
    if topic == 'application-write-scope': names.update(('focus_application_writer.py', 'map_updater_handoff.py'))
    return {'native_tool_versions': profile['tools']['versions'],
        'native_host_tool_hashes': profile['tools']['file_sha256'],
        'native_exporter_hashes': profile['scripts'], 'workflow_version': profile['workflow_version'],
        'verifier_hashes': {name: hashlib.sha256((root / 'tools' / name).read_bytes()).hexdigest() for name in sorted(names)}}


def run(topic, output, workspace, *, verify_existing=False, root=ROOT):
    """Generate metadata only, or compare it with fresh authenticated checks.

    Reuses retained Ghidra dossiers; never reruns extraction/native analysis,
    accesses a device, constructs a patch, or promotes a readiness gate.
    """
    if topic not in TOPICS: raise ValueError('Unknown research topic')
    output = Path(output).resolve()
    if not output.is_relative_to((root / 'derived').resolve()):
        raise ValueError('Research output must stay under derived/')
    if verify_existing:
        if not output.is_file(): raise ValueError('Existing report is required for verification')
        prior = json.loads(output.read_text(encoding='utf-8'))
    elif output.exists(): raise ValueError('Choose a new research output path')
    module_name, native_suffix = TOPICS[topic]
    module = importlib.import_module(module_name)
    source = root / 'sources/extracted-v1.1/S3300Update/firmware/firmware.bin'
    native = root / 'derived/native-analysis-complete' / native_suffix
    inputs = (Path(workspace), source, native)
    if topic == 'usb-entry': inputs += (root / 'derived/native-index-final/native.sqlite',)
    report = module.build_report(*inputs)
    report['research_provenance'] = provenance(topic, report, root)
    if verify_existing:
        if prior != report: raise ValueError('Existing research report is stale or incompatible with current authenticated inputs')
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2); handle.write('\n')
    return {'topic': topic, 'output': str(output), 'verified_existing': verify_existing,
            'source_sha256': report['source_sha256'], 'camera_accessed': False,
            'native_analysis_reused': True, 'executable_trial_allowed': False}
