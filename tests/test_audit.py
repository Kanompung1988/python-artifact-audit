from __future__ import annotations
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("paudit", ROOT / "scripts" / "audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def wheel(self, names, filename="demo-1.0-py3-none-any.whl", modes=None):
        p = self.root / filename
        with zipfile.ZipFile(p, "w") as z:
            for name in names:
                info = zipfile.ZipInfo(name)
                if modes and name in modes:
                    info.create_system = 3
                    info.external_attr = modes[name] << 16
                z.writestr(info, "placeholder")
        return p

    def sdist(self, names, zip_format=False):
        path = self.root / ("demo-1.0.zip" if zip_format else "demo-1.0.tar.gz")
        if zip_format:
            with zipfile.ZipFile(path, "w") as z:
                for name in names: z.writestr(name, "fixture")
        else:
            with tarfile.open(path, "w:gz") as tar:
                for name in names:
                    data = b"fixture"
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        return path

    @property
    def metadata(self):
        return ["demo-1.0.dist-info/METADATA", "demo-1.0.dist-info/WHEEL", "demo-1.0.dist-info/RECORD", "demo/__init__.py"]

    def rules(self, path):
        return [f["rule"] for f in audit.inspect(path)["findings"]]

    def test_clean_wheel(self): self.assertEqual(self.rules(self.wheel(self.metadata)), [])
    def test_missing_metadata(self): self.assertIn("PA004", self.rules(self.wheel(["a.py"])))
    def test_missing_record(self): self.assertIn("PA004", self.rules(self.wheel(self.metadata[:-2]+self.metadata[-1:])))
    def test_ambiguous_dist_info(self): self.assertIn("PA004", self.rules(self.wheel(self.metadata + ["other-1.dist-info/METADATA"])))
    def test_pem(self): self.assertIn("PA002", self.rules(self.wheel(self.metadata + ["src/private.pem"])))
    def test_env(self): self.assertIn("PA002", self.rules(self.wheel(self.metadata + [".env.production"])))
    def test_nested_git(self): self.assertIn("PA003", self.rules(self.wheel(self.metadata + ["src/.git/config"])))
    def test_cache(self): self.assertIn("PA003", self.rules(self.wheel(self.metadata + ["demo/__pycache__/abc.pyc"])))
    def test_parent_path(self): self.assertIn("PA001", self.rules(self.wheel(self.metadata + ["../escape.py"])))
    def test_slash_double(self): self.assertTrue(audit.check_path("src//x.py"))
    def test_windows_drive(self): self.assertTrue(audit.check_path("C:/Users/file.py"))
    def test_backslash(self): self.assertTrue(audit.check_path("a\\..\\x"))
    def test_absolute(self): self.assertTrue(audit.check_path("/root/.env"))
    def test_duplicate_casefold(self): self.assertIn("PA006", self.rules(self.wheel(self.metadata + ["Foo.py", "foo.py"])))
    def test_symlink_zip(self):
        p=self.wheel(self.metadata+["link"],modes={"link":stat.S_IFLNK | 0o777})
        self.assertIn("PA005",self.rules(p))
    def test_clean_tar_sdist(self): self.assertEqual(self.rules(self.sdist(["demo-1.0/PKG-INFO","demo-1.0/pyproject.toml","demo-1.0/demo.py"])),[])
    def test_sdist_missing_pkg_info(self): self.assertIn("PA007", self.rules(self.sdist(["demo-1.0/pyproject.toml"])))
    def test_sdist_missing_pyproject(self): self.assertIn("PA007", self.rules(self.sdist(["demo-1.0/PKG-INFO"])))
    def test_sdist_zip(self): self.assertEqual(self.rules(self.sdist(["demo-1.0/PKG-INFO","demo-1.0/pyproject.toml"],True)),[])
    def test_too_many_entries(self):
        with self.assertRaises(audit.AuditError): audit.inspect(self.wheel(self.metadata),max_entries=2)
    def test_size_cap(self):
        with self.assertRaises(audit.AuditError): audit.inspect(self.wheel(self.metadata),max_total_bytes=1)
    def test_reject_symlink_input(self):
        p=self.wheel(self.metadata)
        link=self.root/"link.whl";link.symlink_to(p)
        with self.assertRaises(audit.AuditError): audit.inspect(link)
    def test_corrupt_zip(self):
        p=self.root/"bad.whl";p.write_bytes(b"notzip")
        with self.assertRaises(audit.AuditError): audit.inspect(p)
    def test_bad_suffix(self):
        p=self.root/"bad.txt";p.write_text("no")
        with self.assertRaises(audit.AuditError): audit.inspect(p)
    def test_cli_json_and_exit_high(self):
        p=self.wheel(self.metadata+["token.key"])
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p),"--format","json","--fail-on","high"],capture_output=True,text=True)
        self.assertEqual(r.returncode,2);self.assertIn("PA002",[x["rule"] for x in json.loads(r.stdout)["findings"]])
    def test_cli_none(self):
        p=self.wheel(self.metadata+["token.key"])
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p),"--fail-on","none"],capture_output=True,text=True)
        self.assertEqual(r.returncode,0)
    def test_cli_input_error(self):
        p=self.root/"x.whl";p.write_bytes(b"broken")
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p)],capture_output=True,text=True)
        self.assertEqual(r.returncode,1)

if __name__ == "__main__": unittest.main()
