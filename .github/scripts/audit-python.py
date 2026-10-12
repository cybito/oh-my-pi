#!/usr/bin/env python3
"""Capture native Python metadata/licenses, never copy the runtime itself.

Inputs: vendor directory, evidence directory, expected target triple.
Output: JSON report plus original metadata, config and license corpus.
Side effects: writes the evidence directory only; no privileges required.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
safe_path = runpy.run_path(str(ROOT / "crates/py/scripts/gen-py-notices.py"))["safe_release_path"]


def main() -> None:
    vendor, output = map(Path, sys.argv[1:3])
    expected_target = sys.argv[3]
    trees = ["python"]
    if expected_target == "aarch64-apple-darwin":
        trees.append("python-release")
    for name in trees:
        tree = vendor / name
        dest = output / name
        dest.mkdir(parents=True, exist_ok=True)
        for filename in ("PYTHON.json", "pyo3-config.txt", ".archive.stamp"):
            shutil.copy2(tree / filename, dest / filename)
        shutil.copytree(tree / "licenses", dest / "licenses", dirs_exist_ok=True)
        metadata = json.loads((tree / "PYTHON.json").read_text())
        zlib_variants = []
        referenced = {metadata["license_path"]}
        for extension, variants in metadata["build_info"]["extensions"].items():
            for variant in variants:
                links = [link for link in variant.get("links", []) if "path_static" in link]
                if not links:
                    continue
                paths = variant.get("license_paths", [])
                referenced.update(paths)
                if any(link["name"] == "z" for link in links):
                    static_files = []
                    for link in links:
                        relative, path = safe_path(tree, link["path_static"], "static library")
                        static_files.append({"name": link["name"], "path": relative,
                                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                    zlib_variants.append({"extension": extension, "links": static_files,
                                          "license_paths": paths})
        absent = []
        for reference in sorted(referenced):
            relative, path = safe_path(tree, reference, "referenced license")
            if not path.is_file():
                absent.append(relative)
        report = {
            "tree": name,
            "archive": (tree / ".archive.stamp").read_text().strip(),
            "python_version": metadata.get("python_version"),
            "target_triple": metadata.get("target_triple"),
            "shipped_licenses": sorted(path.name for path in (tree / "licenses").iterdir() if path.is_file()),
            "absent_referenced_licenses": absent,
            "zlib_variants": zlib_variants,
            "pyo3_config": (tree / "pyo3-config.txt").read_text(),
        }
        (dest / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True), flush=True)
        if report["target_triple"] != expected_target or report["python_version"] != "3.14.7":
            raise SystemExit("Unexpected Python target/version; no compilation permitted.")


if __name__ == "__main__":
    main()
