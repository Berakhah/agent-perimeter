### Task 8: Coordinated disclosure policy

**Files:**
- Create: `docs/security.md`
- Create: `SECURITY.md`
- Test: `tests/docs/test_security_policy.py`

**Interfaces:** none in code. The test is a docs lint, and it exists because a policy that drifts from what the tool actually does is worse than no policy.

DoD 8 names `docs/security.md`; GitHub looks for `SECURITY.md` at the root. `docs/security.md` is canonical and `SECURITY.md` is a short pointer carrying the contact address, so the two can never disagree on the one field that matters.

- [ ] **Step 1: RED — the policy must contain what the brief requires**

Create `tests/docs/test_security_policy.py`:

```python
import re
from pathlib import Path

POLICY = Path("docs/security.md")
REQUIRED_SECTIONS = [
    "## Reporting a vulnerability in Agent Perimeter",
    "## What we do when we find something in your server",
    "## Embargo",
    "## Right of reply",
    "## Secrets",
    "## What we publish",
    "## Digest salt release",
]


def test_every_required_section_is_present() -> None:
    body = POLICY.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in body, f"missing: {section}"


def test_the_embargo_length_matches_the_decision() -> None:
    assert "90 days" in POLICY.read_text(encoding="utf-8")


def test_secrets_bypass_the_embargo_clock() -> None:
    body = POLICY.read_text(encoding="utf-8").lower()
    assert "never publish" in body and "never validate" in body


def test_root_pointer_carries_the_same_contact() -> None:
    contact = re.search(r"<([^>]+@[^>]+)>", POLICY.read_text(encoding="utf-8"))
    assert contact is not None
    assert contact.group(1) in Path("SECURITY.md").read_text(encoding="utf-8")
```

Run: `uv run pytest tests/docs/`
Expected: `FileNotFoundError: docs/security.md`

- [ ] **Step 2: GREEN — write the policy**

Create `docs/security.md` covering, under the exact headings above:

- **Reporting a vulnerability in Agent Perimeter** — contact address, PGP key or GitHub private advisory, expected acknowledgement time.
- **What we do when we find something in your server** — we contact the maintainer at the address published in the registry entry or repository, with the finding, the reproduction, and the date we intend to publish aggregate statistics.
- **Embargo — 90 days** from first contact. Aggregate statistics may publish before the clock expires because they name nobody; nothing that identifies a server publishes at any point, before or after.
- **Right of reply** — a maintainer may dispute a finding, supply context, or request that the check be re-run against a corrected release. Disputed findings are re-run, and the outcome is recorded in the changelog whichever way it goes.
- **Secrets** — a credential discovered in a public artifact is reported to the owner and the hosting platform immediately. **It bypasses the embargo clock entirely. It is never published, never included in raw data, and never validated against a live service.**
- **What we publish** — aggregate statistics only. No named third-party server, reply or no reply. Raw data keyed by digest.
- **Digest salt release** — the per-run salt is published when the embargo expires; until then, digests are stable pseudonyms so anyone can verify the arithmetic without being handed a target list.

Create `SECURITY.md` at the root: three sentences plus the contact address plus a link to `docs/security.md`.

- [ ] **Step 3: Wire into CI**

Add `uv run pytest tests/docs/` to the CI test job so the policy cannot silently drift from the embargo decision.

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/docs/
git add docs/security.md SECURITY.md tests/docs/ .github/workflows/ci.yml
git commit -m "docs: coordinated disclosure policy with an enforced structure (DoD 8)"
```

---

