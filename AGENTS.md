# SignalLayer agent entry point

Before investigating, planning, changing code, or proposing a merge in this repository:

1. Read `ENGINEERING.md` in full. It is the adopted engineering policy; this file adds no substitute rules.
2. Read the applicable milestone contract, architecture documents, and `docs/development/CURRENT-STATUS.md`. Verify the status against repository history and retained evidence before relying on it.
3. Follow `ENGINEERING.md` for scope, owner approval, independent review, evidence, regression tests, and release gates. If instructions conflict, surface the conflict and stop the affected work rather than silently choosing.
4. For nontrivial tasks, state the concrete outcome, acceptance evidence (including a negative test when applicable), out-of-scope boundaries, `Release-Identity`, and `CoreOS-Surface-Change` as required by `ENGINEERING.md`.
5. Implement and test within the explicitly authorized task. Resolve ordinary implementation defects within scope; escalate only the decisions and changes `ENGINEERING.md` reserves for the product owner. Never treat passing tests as permission to merge, modify protected CoreOS surfaces, or publish.
6. At a checkpoint, report in plain language what actually works, what remains UNPROVEN or BLOCKED, and the next bounded engineering action. Update the status file only when the recorded evidence or authorization changes; do not invent a new planning/review cycle.

The status file is a handoff aid, not an approval authority. The existing architecture contracts and release evidence remain authoritative for technical claims.
