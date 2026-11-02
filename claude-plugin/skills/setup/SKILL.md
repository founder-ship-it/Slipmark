---
name: setup
description: Set up Slipmark in this repository (attestation directory, report-only GitHub workflow, agent instructions).
disable-model-invocation: true
---

Show the plan first, without writing anything:

```bash
npx --yes slipmark@0.6.2 init --dry-run
```

Tell the user which files would be created or updated, then ask before running:

```bash
npx --yes slipmark@0.6.2 init
```

`init` never overwrites a workflow the user wrote, and only edits text between its own `<!-- slipmark:begin -->` and `<!-- slipmark:end -->` markers in AGENTS.md, CLAUDE.md and similar files.

Afterwards, remind the user to:

1. Commit the new files, including `.slipmark/attestations/`.
2. Set `fail-on-refusal: "true"` in `.github/workflows/slipmark.yml` once verdicts are being recorded, to enforce the gate.
