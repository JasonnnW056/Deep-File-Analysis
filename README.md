# Deep-File-Analysis

> ⚠️ **Status:** Still in development. Features and interfaces may change.

A self-hosted malware triage pipeline. It combines static analysis (YARA, PE inspection) with [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) detonation, maps observed behavior to MITRE ATT&CK, and produces an explainable verdict with a confidence score and key evidence.

## Features

- **Static analysis**: file hashing, string extraction, PE header inspection, and YARA rule matching.
- **Sandbox detonation**: automated submission to CAPE Sandbox, running samples in an isolated Windows VM with a snapshot revert after every run.
- **MITRE ATT&CK mapping**: observed behavior is translated into technique IDs that analysts already know.
- **Combined scoring**: static and dynamic signals are merged into a verdict (`malicious`, `suspicious`, or `benign`) with a confidence score.
- **Explainable reports**: every verdict comes with the specific evidence behind it, not just a number.
- **Scan history**: results are stored in SQLite for review and for measuring accuracy against labeled test samples.
