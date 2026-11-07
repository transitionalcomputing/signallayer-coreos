# P3-1d source controls

See `management-lifecycle/MODEL.md`. The Rust tests supply only in-memory
observations. Fake pidfds, durable receipts and process events do not establish
native runtime isolation or crash consistency. Linux execution remains source-
model acceptance, not a live lifecycle test. The mutation harness runs only an
explicit compiler and generated test binary in a temporary output directory.
No Podman, live systemd, accounts or F5 executable is invoked by these tests.
