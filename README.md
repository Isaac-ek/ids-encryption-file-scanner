# Website scanner consolidated into SecureStream

The website-checking engine is now part of [SecureStream / IDS X Enc](https://github.com/Isaac-ek/ids-encryption-file-scanner/tree/codex/unified-security-console), together with the trained intrusion detector, file encryption and shared audit history.

Use that repository for the maintained application, installation instructions and tests. The imported engine lives under `web_scanner/` and retains this project's license.

The duplicate standalone application, web UI and deployment entrypoints have been removed from this branch. Earlier versions remain in this repository's Git history. The original standalone source is recoverable at commit `41f4c58`.

The consolidated implementation is reviewed in [the consolidation PR](https://github.com/Isaac-ek/ids-encryption-file-scanner/pull/1). Its verified deployment target is Docker; a combined public deployment has not yet been published.
