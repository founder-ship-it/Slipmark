---
name: verify
description: Check every Slipmark verdict in this repository against the files as they are now, and explain any refusal.
disable-model-invocation: true
---

Run the Slipmark gate on the current working tree:

```bash
npx --yes slipmark@0.6.2 verify
```

Then report the result in plain language:

- **Exit 0**: every verdict matches the files as they are now. Say how many were verified.
- **`hash_mismatch`**: the file changed after the verdict. Name the file and who gave the verdict. Offer to re-read it and attest again.
- **`subject_missing`**: an attested file was deleted or moved.
- **`verdict_not_passing`**: someone recorded `fail` or `blocked`. That is an honest result, not an error. Quote the note from the attestation file in `.slipmark/attestations/` if there is one.
- **`unattested`**: no verdicts yet, or a required file has none. Suggest `/slipmark:setup` if the repository has no `.slipmark/` directory.

Do not edit or delete attestation files to make the gate pass.
