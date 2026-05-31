# Fixor on a realistic FastAPI app — a verifiable detection proof

This repository lets you check, with your own eyes, how Fixor's business-logic
detectors behave on a realistic FastAPI app: which planted vulnerabilities they
catch, and whether they stay silent on the safe routes sitting right beside them.

**Auditable, not runnable.** The Fixor engine is closed-source, so you cannot
re-run the scan yourself from this repo. What you *can* do — and what this repo
is built for — is verify the test is fair and verify the results against the
raw tool output. You don't need to trust our numbers; you need to read the code.

## How to verify this yourself (no tools needed)

1. Read the seven `.py` files in `corpus/` — ~210 lines total. Decide for
   yourself which routes are genuinely vulnerable and which are genuinely safe.
2. Compare your judgment to `corpus/ground-truth.json` (the planted vulns and
   the safe controls, with the reason for each). The `.py` files carry **no**
   security-tell comments — a real PR doesn't annotate its own bugs.
3. Compare both against the raw scan logs in `logs/`. Confirm each flagged
   finding lands on a route you judged vulnerable, and that no finding lands on
   one you judged safe.

## Scorecard

Measured across **5 runs on the published engine build**, production model
`claude-sonnet-4-6`, temperature 0:

| Metric | Result |
|---|---|
| Planted vulnerable routes detected (critical) | **3 / 3, all 5 runs** |
| False positives on the 6 safe control routes | **0 / 6, all 5 runs** (every finding lands on a genuinely vulnerable route) |

The three planted routes, and how each was caught:

| Planted route | Truth | Detected | Carries its correct label? |
|---|---|---|---|
| `POST /admin/users/{user_id}/role` | admin-check | ✅ 5/5 | ✅ `admin_check` present |
| `GET /items/{item_id}` | idor | ✅ 5/5 | ✅ `idor` (clean, single) |
| `DELETE /users/{user_id}` | auth-bypass | ✅ 5/5 | ✅ `auth_bypass` present |

The six control routes (`GET /health`, `GET /users/me`, `PATCH /users/me`,
`GET /admin/stats`, `GET /items`, `DELETE /items/{item_id}`) drew **zero**
findings in all 5 runs.

### Reconciling the finding count (why a log shows 7 findings, not 3)

A run emits **6–7 findings for the 3 vulnerable routes**, because more than one
detector fires on the same route. Mapping every finding to its route:

| Route | Findings (labels) |
|---|---|
| `POST /…/role` | `auth_bypass` + `admin_check` + `idor` (the `idor` one is nondeterministic; see below) |
| `GET /items/{item_id}` | `idor` |
| `DELETE /users/{user_id}` | `auth_bypass` + `admin_check` + `idor` |

Every one of these findings is on a **genuinely vulnerable route**. None is on a
safe control. So the count is higher than 3, but the false-positive count is
still 0. Of the 5 runs, 3 emitted 7 findings and 2 emitted 6 — the difference is
a single redundant `idor` finding on the admin role-route that the model flags
nondeterministically. Detection of the 3 planted routes was 3/3 in **all 5**.

## Methodology

- **Mapping rule (pre-registered):** each finding is mapped to a route by the
  route its description names, cross-checked against the finding's line anchor.
- **No tells:** the scanned `.py` files contain no comments hinting at the
  vulnerabilities. Ground truth lives only in `ground-truth.json`, which a
  `--ext=py` scan ignores.
- **Cost:** the scanner's pre-run estimate is ~$0.23/run. This is **estimated,
  not measured** — the CLI does not meter actual spend.
- **Scope:** this proof demonstrates **detection**. Automated remediation is out
  of scope and not shown.

## Limitations (read these — they are part of the proof)

We disclose what this proof does **not** establish, plainly:

1. **Detector labels are cross-wired, and this can blur a finding's reasoning.**
   A vulnerable route is often flagged by more than one detector, so the *label*
   (`auth_bypass` vs `admin_check` vs `idor`) is frequently not the textbook
   class for that route. Each route does carry its correct label among its
   findings. But when a detector fires on a route outside its class, its
   *explanation* can misdescribe the mechanism. Concretely: on
   `POST /admin/users/{user_id}/role`, the `auth_bypass` finding calls the route
   "unauthenticated," yet `CurrentUser` (`Depends(get_current_user)` — see
   `corpus/app/auth.py`) does authenticate it. The route is
   authenticated-but-not-admin-gated, which the `admin_check` finding on the same
   route describes correctly. So: every finding lands on a genuinely vulnerable
   route, but a cross-wired finding's *mechanism description* can be imprecise.
   That labeling work is tracked but not yet shipped.
2. **Finding count is inflated.** One vulnerable route may draw two or three
   findings with different labels. This reads as over-eager, not wrong: the
   false-positive count on safe routes is 0. The count is also mildly
   nondeterministic (6–7 across runs).
3. **One corpus.** This is a single FastAPI app that we authored. It proves the
   method works on this realistic, planted corpus — it says **nothing** about
   recall on code it hasn't seen, and it is **not** a precision/recall figure. A
   real-repo true-negative (scanning a well-known, well-secured public project
   and showing zero findings) is the planned next step; it is not in this repo.
4. **Auditable, not runnable.** Because the engine is private, you verify by
   reading the corpus and cross-checking the logs, not by re-executing the scan.

## Appendix: raw scan logs

`logs/` holds the verbatim scanner output for each run. They are here so you can
verify the scorecard against the actual tool output — they are the evidence, not
a polished summary. They include the imperfections disclosed above (multiple
labels per route, count variance). Nothing is hidden.

Note on paths: each log's `Scanned path:` header reads
`fixtures/real-shape/fastapi-saas` — the corpus's location in our build tree.
In this repo those exact files live under `corpus/`, byte-for-byte identical
(verified by `diff -r` and per-file SHA-256). The per-finding paths
(`app/routers/…`) map directly onto `corpus/app/routers/…`.
