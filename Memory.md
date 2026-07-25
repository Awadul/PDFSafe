# PDFSafe - Memory Bank

## Architecture & Decisions
- Monolithic desktop/CLI app with optional server backend target.
- Core package: `src/pdfsafe` (`analysis`, `ai`, `local`, `desktop`, `api`, `cli`).

## Current Feature State
- **Static Analysis Engine**: Complete & Verified (Parsing, JS/URL extraction, YARA signatures, Noisy-OR scoring).
- **AI Triage & NVIDIA Integration**: Complete & Verified (`.env` active with NVIDIA Endpoint `https://integrate.api.nvidia.com/v1` and model `stepfun-ai/step-3.7-flash`).
- **Desktop GUI (`pdfsafe-desktop`)**: Complete & Installed (`PySide6 6.11.1`, `shiboken6`, `watchdog`, `pywin32` installed and verified).
- **CLI (`pdfsafe`)**: Complete & Verified (`scan`, `watch`, `rules`, `config`, `version`).
- **Test Suite**: 100% passing (131 passed, 20 skipped).

## Active Configuration (`.env`)
- `PDFSAFE_AI_ENABLED=true`
- `PDFSAFE_AI_PROVIDER=custom`
- `PDFSAFE_CUSTOM_AI_BASE_URL=https://integrate.api.nvidia.com/v1`
- `PDFSAFE_CUSTOM_AI_MODEL=stepfun-ai/step-3.7-flash`
