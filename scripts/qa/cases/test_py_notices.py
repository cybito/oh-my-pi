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

	def metadata(self, links, license_paths, extension="fixture", variant="default", **identity):
		(self.vendor / "PYTHON.json").write_text(
			json.dumps({
				"python_version": "3.14.7",
				"license_path": "licenses/LICENSE.cpython.txt",
				**identity,
				"build_info": {
					"extensions": {
						extension: [{
							"links": links,
							"license_paths": license_paths,
							"variant": variant,
						}],
					},
				},
			}),
			encoding="utf-8",
		)

	def audited_zlib(self, links=None, license_paths=None, extension="zlib", variant="default", **identity):
		# The GNU ARM64 audit in Actions run 38314581444 observed this exact
		# identity, sole static link, alternative pair, and classic-zlib corpus.
		self.ship("LICENSE.zlib.txt", "Classic zlib 1.3.2 notice\n")
		(self.vendor / ".archive.stamp").write_text(
			"cpython-3.14.7+20260807-aarch64-unknown-linux-gnu-freethreaded+debug-full\n",
			encoding="utf-8",
		)
		self.metadata(
			links if links is not None else [{"name": "z", "path_static": "build/lib/libz.a"}],
			license_paths if license_paths is not None else [
				"licenses/LICENSE.zlib-ng.txt",
				"licenses/LICENSE.zlib.txt",
			],
			extension=extension,
			variant=variant,
			**{
				"version": "8",
				"python_version": "3.14.7",
				"target_triple": "aarch64-unknown-linux-gnu",
				"build_options": "freethreaded+debug",
				**identity,
			},
		)

	def test_audited_classic_zlib_selects_shipped_notice(self):
		self.audited_zlib()
		text, native_count, wheel_count = NOTICES.generate(self.vendor)
		self.assertIn("Classic zlib 1.3.2 notice", text)
		self.assertIn("Authoritative release license reference: licenses/LICENSE.zlib.txt", text)
		self.assertNotIn("LICENSE.zlib-ng.txt", text)
		self.assertEqual((native_count, wheel_count), (1, 0))

	def test_unaudited_release_identity_keeps_missing_license_error(self):
		for identity in (
			{"version": "9"},
			{"python_version": "3.14.8"},
			{"target_triple": "x86_64-unknown-linux-gnu"},
			{"build_options": "freethreaded+pgo+lto"},
		):
			with self.subTest(identity=identity):
				self.audited_zlib(**identity)
				with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib-ng.txt"):
					NOTICES.generate(self.vendor)

	def test_missing_or_unknown_archive_stamp_keeps_missing_license_error(self):
		self.audited_zlib()
		(self.vendor / ".archive.stamp").unlink()
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib-ng.txt"):
			NOTICES.generate(self.vendor)
		(self.vendor / ".archive.stamp").write_text(
			"cpython-3.14.7+20260808-aarch64-unknown-linux-gnu-freethreaded+debug-full\n",
			encoding="utf-8",
		)
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib-ng.txt"):
			NOTICES.generate(self.vendor)

	def test_unaudited_zlib_variant_keeps_missing_license_error(self):
		for changes in (
			{"extension": "other"},
			{"variant": "other"},
			{"links": [{"name": "other", "path_static": "build/lib/libz.a"}]},
			{"links": [{"name": "z", "path_static": "build/lib/other.a"}]},
		):
			with self.subTest(changes=changes):
				self.audited_zlib(**changes)
				with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib-ng.txt"):
					NOTICES.generate(self.vendor)

	def test_mixed_links_cannot_use_zlib_exception(self):
		self.ship("LICENSE.bar.txt", "Bar license text\n")
		self.audited_zlib(links=[
			{"name": "z", "path_static": "build/lib/libz.a"},
			{"name": "bar", "path_static": "build/lib/libbar.a"},
		])
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib-ng.txt"):
			NOTICES.generate(self.vendor)

	def test_audited_identity_does_not_hide_missing_mixed_component_license(self):
		self.audited_zlib(
			links=[
				{"name": "z", "path_static": "build/lib/libz.a"},
				{"name": "bar", "path_static": "build/lib/libbar.a"},
			],
			license_paths=[
				"licenses/LICENSE.zlib-ng.txt",
				"licenses/LICENSE.zlib.txt",
				"licenses/LICENSE.bar.txt",
			],
		)
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.bar.txt"):
			NOTICES.generate(self.vendor)

	def test_extra_required_path_cannot_use_zlib_exception(self):
		self.audited_zlib(license_paths=[
			"licenses/LICENSE.zlib-ng.txt",
			"licenses/LICENSE.zlib.txt",
			"licenses/LICENSE.required.txt",
		])
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.required.txt"):
			NOTICES.generate(self.vendor)

	def test_missing_classic_zlib_text_cannot_use_exception(self):
		self.audited_zlib()
		(self.vendor / "licenses/LICENSE.zlib.txt").unlink()
		self.ship("LICENSE.zlib-ng.txt", "Zlib-ng notice\n")
		with self.assertRaisesRegex(SystemExit, "absent license file licenses/LICENSE.zlib.txt"):
			NOTICES.generate(self.vendor)

	def test_existing_zlib_ng_reference_is_preserved(self):
		self.audited_zlib()
		self.ship("LICENSE.zlib-ng.txt", "Zlib-ng notice\n")
		text, _, _ = NOTICES.generate(self.vendor)
		self.assertIn("Classic zlib 1.3.2 notice", text)
		self.assertIn("Zlib-ng notice", text)
		self.assertIn("Authoritative release license reference: licenses/LICENSE.zlib-ng.txt", text)

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
