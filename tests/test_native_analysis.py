"""Native-analysis provenance, archive confinement and import-byte checks."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from native_tools import checked_members
from native_analysis import verify_loaded, compatible_profile


class NativeAnalysisTests(unittest.TestCase):
    def test_tool_zip_rejects_traversal_absolute_drive_and_symlink(self):
        for name in ("../outside", "/root/file", "C:/file", "safe/../../escape"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                raw=BytesIO()
                with zipfile.ZipFile(raw,"w") as archive:archive.writestr(name,b"x")
                with zipfile.ZipFile(raw) as archive,self.assertRaises(ValueError):list(checked_members(archive,Path(directory)))
        raw=BytesIO();link=zipfile.ZipInfo("safe/link");link.external_attr=0xa1ff<<16
        with zipfile.ZipFile(raw,"w") as archive:archive.writestr(link,"../outside")
        with tempfile.TemporaryDirectory() as directory,zipfile.ZipFile(raw) as archive,self.assertRaises(ValueError):
            list(checked_members(archive,Path(directory)))

    def test_imported_memory_hash_and_extent_must_match(self):
        manifest={"regions":[{"virtual_start":4096,"size":4,"sha256":"hash","name":"code"}]}
        image={"language":"MIPS:LE:32:default","memory":[{"start":"1000","size":4,"sha256":"hash"}]}
        self.assertTrue(verify_loaded(image,manifest))
        self.assertTrue(verify_loaded({**image,"memory":image["memory"]+[{"start":".shstrtab::00000000","size":20}]},manifest))
        for key,value in (("size",8),("sha256","changed"),("start","2000")):
            altered={"language":image["language"],"memory":[{**image["memory"][0],key:value}]}
            with self.assertRaises(ValueError):verify_loaded(altered,manifest)
        with self.assertRaises(ValueError):verify_loaded({**image,"language":"MIPS:BE:32:default"},manifest)

    def test_resume_rejects_changed_source_tools_scripts_and_workflow(self):
        original={"source_sha256":"source","analysis_sha256":"image","scripts":{"export":"hash"},
                  "tools":{"version":"12.1.4"},"workflow_version":2,"runner_sha256":"first"}
        self.assertTrue(compatible_profile(original,{**original,"runner_sha256":"verification-only-change"}))
        for key,value in (("source_sha256","changed"),("scripts",{}),("tools",{}),("workflow_version",3)):
            self.assertFalse(compatible_profile(original,{**original,key:value}))


if __name__=="__main__":unittest.main()
