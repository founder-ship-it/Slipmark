---
name: attest-verdicts
description: Record a Slipmark attestation whenever you give a verdict (a review passed or failed, an audit cleared, a spec approved, tests judged passing) in a repository that has a .slipmark/ directory or mentions Slipmark in AGENTS.md or CLAUDE.md. Binds the verdict to the SHA-256 of every file it was based on.
---

# Attest your verdicts with Slipmark

This repository gates merges on Slipmark: a verdict only counts if it is bound
to the exact bytes of the files it was about. When you give a verdict, record
it straight away.

## When

Any time you conclude that something passes or fails: a code review, a check
against a spec, a security or compliance audit, a judgement that tests are
sufficient. Not for routine edits where you give no verdict.

## How

```bash
npx slipmark@0.7.0 attest --by <your-role> --verdict <pass|fail|blocked> \
  --subject <file> --subject <file> \
  --note "<one line: what you checked and the outcome>"
```

- `--by`: a short role name, for example `reviewer`, `security-audit`, `qa`.
- `--subject`: every file the verdict is based on. Include the spec or
  requirements you checked against, not only the file under review.
- `--verdict pass` (or `cleared`) only when it genuinely passes. Use `fail` or
  `blocked` otherwise, and say why in `--note`.
- Never attest a file you did not read in this session.

Then confirm:

```bash
npx slipmark@0.7.0 verify
```

Exit 0 means every verdict matches the files as they are now. A `fail` verdict
shows as refused, which is correct: it tells the reviewer the work is not
finished.

## After

- Commit the new file in `.slipmark/attestations/` with the change.
- If you edit a file you already attested, read it again and attest again.
  The old verdict stops counting the moment the file changes.
- Never edit or delete attestation files by hand.
