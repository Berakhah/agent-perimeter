// node --test: the pretest fixture renderer must not hard-require `uv`.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "render-fixtures.mjs");
const root = path.resolve(here, "..", "..");

test("renders the fixtures with whatever interpreter is available", () => {
  const r = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(path.join(root, "web", "tests", "fixtures", "report.html")));
  assert.ok(existsSync(path.join(root, "web", "tests", "fixtures", "census.html")));
});

test("names every interpreter it tried when none works", () => {
  const empty = mkdtempSync(path.join(tmpdir(), "ap-noenv-"));
  const r = spawnSync(process.execPath, [script], {
    encoding: "utf8",
    env: { ...process.env, PATH: empty, Path: empty, AP_ROOT: empty, AP_PYTHON: "" },
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /uv run python/);
  assert.match(r.stderr, /\.venv/);
  assert.match(r.stderr, /Install uv or create \.venv/);
});
