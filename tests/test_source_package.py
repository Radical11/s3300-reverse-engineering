from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import package_development as package


class SourcePackageTests(unittest.TestCase):
    def test_package_determinism_and_vendor_private_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for filename in ('README.md','CONTRIBUTING.md','.gitignore','LICENSE','tools/tool.py','tools/vendor/secret.py',
                             'samples/photo.jpg','sources/firmware.bin','derived/analysis.elf',
                             'tests/test_example.py','docs/development/README.md'):
                path=root/filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(filename)
            first=root/'derived/one.zip';second=root/'derived/two.zip'
            with patch.object(package,'ROOT',root):
                a=package.build(first,root);b=package.build(second,root)
            self.assertEqual(a['sha256'],b['sha256'])
            with zipfile.ZipFile(first) as archive:
                names=archive.namelist()
                self.assertIn('.gitignore',names)
                self.assertIn('CONTRIBUTING.md',names)
                self.assertIn('tools/tool.py',names)
                self.assertFalse(any(name.startswith(('samples/','sources/','derived/','tools/vendor/')) for name in names))
            before=first.read_bytes()
            with self.assertRaises(ValueError):package.build(first,root)
            self.assertEqual(first.read_bytes(),before)


if __name__=='__main__':unittest.main()
