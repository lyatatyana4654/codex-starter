"""Credential/private filenames are rejected without opening their contents."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("starter_distribution", ROOT / "scripts/check_distribution.py")
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def check(self):
        output = io.StringIO()
        with mock.patch.object(distribution, 'ROOT', self.root), contextlib.redirect_stdout(output):
            result = distribution.main()
        return result, output.getvalue()

    def test_env_variants_rejected_without_read(self):
        for name in ('.env', '.env.local', '.env.production', 'nested/.env.test'):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'\xff\x00')
                with mock.patch.object(Path, 'read_text', side_effect=AssertionError('must not read secrets')):
                    result, output = self.check()
                self.assertEqual(result, 1, output)
                path.unlink()

    def test_env_example_allowed(self):
        (self.root / '.env.example').write_text('PLACEHOLDER=example\n')
        self.assertEqual(self.check()[0], 0)

    def test_root_business_tree_rejected_without_read(self):
        path = self.root / '.business/private.md'
        path.parent.mkdir()
        path.write_bytes(b'\xff\x00')
        with mock.patch.object(Path, 'read_text', side_effect=AssertionError('must not read private context')):
            result, output = self.check()
        self.assertEqual(result, 1, output)

    def test_business_template_allowed(self):
        path = self.root / 'payload/business-template/INDEX.md'
        path.parent.mkdir(parents=True)
        path.write_text('# Clean template\n')
        self.assertEqual(self.check()[0], 0)

    def test_directory_and_broken_symlinks_rejected(self):
        directory = self.root / 'ordinary-directory'
        directory.mkdir()
        for destination in (directory, self.root / 'missing'):
            with self.subTest(destination=destination.name):
                link = self.root / 'link'
                link.symlink_to(destination, target_is_directory=True)
                result, output = self.check()
                self.assertEqual(result, 1, output)
                self.assertIn('Symlink:', output)
                link.unlink()

    def test_empty_private_business_directory_rejected(self):
        (self.root / '.business').mkdir()
        self.assertEqual(self.check()[0], 1)


if __name__ == '__main__':
    unittest.main()
