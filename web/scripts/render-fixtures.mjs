// `npm run pretest`: render web/tests/fixtures/{report,census}.html from the
// real Jinja renderers (analysis/render_web_fixtures.py) with the first
// Python that works. `uv` is the project's normal entry point but is not
// required on PATH: a checked-out `.venv` (what `uv sync` creates) or a bare
// `python` with the project installed also works. Set AP_PYTHON to force an
// interpreter.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = process.env.AP_ROOT || path.resolve(here, "..", "..");
const renderer = path.join("analysis", "render_web_fixtures.py");

const candidates = [];
if (process.env.AP_PYTHON) candidates.push({ label: process.env.AP_PYTHON, cmd: process.env.AP_PYTHON, args: [] });
candidates.push({ label: "uv run python", cmd: "uv", args: ["run", "python"] });
for (const venv of [path.join(root, ".venv", "Scripts", "python.exe"), path.join(root, ".venv", "bin", "python")]) {
  if (existsSync(venv)) candidates.push({ label: venv, cmd: venv, args: [] });
  else candidates.push({ label: `${venv} (absent)`, cmd: null, args: [] });
}
candidates.push({ label: "python3", cmd: "python3", args: [] });
candidates.push({ label: "python", cmd: "python", args: [] });

const tried = [];
for (const c of candidates) {
  if (c.cmd === null) {
    tried.push(`${c.label}`);
    continue;
  }
  const r = spawnSync(c.cmd, [...c.args, renderer], { cwd: root, stdio: ["ignore", "inherit", "pipe"], encoding: "utf8", shell: false });
  if (r.status === 0) process.exit(0);
  const why = r.error ? r.error.code : `exit ${r.status}: ${(r.stderr || "").trim().split("\n").pop()}`;
  tried.push(`${c.label} -> ${why}`);
  // A found interpreter that ran the script and failed is a real error in
  // the renderer, not a missing interpreter; do not mask it by moving on.
  if (!r.error && r.status !== 0 && !/No module named|ModuleNotFoundError/.test(r.stderr || "")) {
    process.stderr.write(r.stderr || "");
    break;
  }
}
process.stderr.write(
  `Could not render web/tests/fixtures. Interpreters tried:\n  ${tried.join("\n  ")}\n` +
    "Install uv or create .venv (`uv sync`), or set AP_PYTHON to a Python with the project installed.\n",
);
process.exit(1);
