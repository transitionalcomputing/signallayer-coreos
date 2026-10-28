# Publication redactions

The original evidence remains restricted on the authorized development host.
Before public publication, two files were transformed deterministically:

| File | Original SHA-256 | Publication-only substitutions |
| --- | --- | --- |
| `report.json` | `5563838e25b7148a1d59f9bc5f6e634ca9bde7f98398238f7417f6c6fb4b1319` | Absolute development-host input, output and evidence paths were replaced by descriptive placeholders. |
| `serial.log` | `8adfe8c20fb5963b39c61846b9a1de1b9b5f63c69ee0f13ef5f295d9fd8287b1` | Host CPU model, ephemeral guest filesystem/machine/boot/invocation/event identifiers, and QEMU user-network guest addresses were replaced by descriptive placeholders. |

No command exit code, structured guest evidence record, security result, AVC,
lifecycle marker, input checksum or evaluator predicate was changed. The
published `guest-evidence.tsv` remains byte-for-byte identical to the original
and still exactly matches `report.json`'s evidence object. Replaying the strict
evaluator over the sanitized package returns 28/28 PASS. The serial file's
original CR, CRLF and LF record separators and terminal control bytes were
preserved.

The original local execution commit was
`4e5f3ecba89dcaa6205aa3b86995d50ac81ba5ee`. Prepublication history was
rewritten to remove personal email metadata and generated Python bytecode. The
published source-equivalent commit is recorded in `SOURCE_COMMIT`; its three
executable experiment files are byte-for-byte identical to those used for the
successful run.
