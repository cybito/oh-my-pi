#!/usr/bin/env python3
"""Strict license-corpus contracts for the embedded Python notice generator.

Run without an omp binary or runtime archive with
``python3 -m unittest discover -s scripts/qa/cases -p test_py_notices.py``.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

COVERS: dict[str, list[str]] = {"py": [], "rpc": []}

SCRIPT = Path(__file__).resolve().parents[3] / "crates/py/scripts/gen-py-notices.py"
SPEC = importlib.util.spec_from_file_location("gen_py_notices", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)


class ReleaseLicenseCorpus(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory(prefix="omp-py-notices-")
		self.addCleanup(self.temporary.cleanup)
		self.vendor = Path(self.temporary.name)
		(self.vendor / "licenses").mkdir()
		self.ship("LICENSE.cpython.txt", "CPython license text\n")

	def ship(self, filename, text):
		(self.vendor / "licenses" / filename).write_text(text, encoding="utf-8")

	def metadata(self, links, license_paths):
		(self.vendor / "PYTHON.json").write_text(
			json.dumps({
				"python_version": "3.14.7",
				"license_path": "licenses/LICENSE.cpython.txt",
				"build_info": {
					"extensions": {
						"fixture": [{
							"links": links,
							"license_paths": license_paths,
						}],
					},
				},
			}),
			encoding="utf-8",
		)

	def test_missing_required_sibling_license_fails(self):
		self.ship("LICENSE.present.txt", "Shipped required text\n")
		self.metadata(
			[{"name": "foo", "path_static": "build/lib/libfoo.a"}],
			["licenses/LICENSE.present.txt", "licenses/LICENSE.required.txt"],
		)
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.required.txt"):
			NOTICES.generate(self.vendor)

	def test_mixed_static_components_do_not_hide_missing_license(self):
		self.ship("LICENSE.bar.txt", "Bar license text\n")
		self.metadata(
			[
				{"name": "foo", "path_static": "build/lib/libfoo.a"},
				{"name": "bar", "path_static": "build/lib/libbar.a"},
			],
			["licenses/LICENSE.foo.txt", "licenses/LICENSE.bar.txt"],
		)
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.foo.txt"):
			NOTICES.generate(self.vendor)

	def test_audited_zstd_fallback_preserves_other_required_paths(self):
		self.ship("LICENSE.present.txt", "Shipped required text\n")
		self.metadata(
			[{"name": "zstd", "path_static": "build/lib/libzstd.a"}],
			["licenses/LICENSE.zstd.txt", "licenses/LICENSE.present.txt"],
		)
		text, native_count, wheel_count = NOTICES.generate(self.vendor)
		self.assertIn("audited fallback for licenses/LICENSE.zstd.txt (facebook/zstd v1.5.7 LICENSE)", text)
		self.assertIn("Shipped required text", text)
		self.assertEqual((native_count, wheel_count), (1, 0))
		self.metadata(
			[{"name": "zstd", "path_static": "build/lib/libzstd.a"}],
			["licenses/LICENSE.zstd.txt", "licenses/LICENSE.required.txt"],
		)
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.required.txt"):
			NOTICES.generate(self.vendor)


if __name__ == "__main__":
	unittest.main()
