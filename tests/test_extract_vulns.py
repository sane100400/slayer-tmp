from __future__ import annotations

from tools.extract_vulns import load_files


def test_load_files_recurses_into_repo_and_skips_vendor_dirs(tmp_path):
    route = tmp_path / "src" / "api" / "users.js"
    route.parent.mkdir(parents=True)
    route.write_text(
        'const express = require("express");\n'
        "function search(name) {\n"
        "  return db.query(`SELECT * FROM users WHERE name = '${name}'`);\n"
        "}\n",
        encoding="utf-8",
    )

    vendored = tmp_path / "node_modules" / "pkg" / "server.js"
    vendored.parent.mkdir(parents=True)
    vendored.write_text('const express = require("express");\n', encoding="utf-8")

    files = load_files(tmp_path)

    assert files == [(str(route), ".js")]


def test_load_files_skips_files_over_size_limit(tmp_path):
    small = tmp_path / "app.py"
    small.write_text("from flask import Flask\n", encoding="utf-8")
    large = tmp_path / "bundle.js"
    large.write_text("x" * 30, encoding="utf-8")

    files = load_files(tmp_path, max_file_bytes=25)

    assert files == [(str(small), ".py")]


def test_load_files_skips_non_service_dirs(tmp_path):
    app = tmp_path / "backend" / "api" / "server.py"
    app.parent.mkdir(parents=True)
    app.write_text("from flask import Flask\n", encoding="utf-8")
    docs = tmp_path / "docs" / "dashboard.html"
    docs.parent.mkdir()
    docs.write_text("<script>console.log('report')</script>\n", encoding="utf-8")

    files = load_files(tmp_path)

    assert files == [(str(app), ".py")]
