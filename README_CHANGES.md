# Changes in vscpl2drv-tcpiplink

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- Add scripts/download-artifacts.sh to download and verify the newest CI build artifacts
- CI writes a SHA256SUMS-<artifact> checksum file into every uploaded build artifact
- Added curl (3bb6707)
- Fixed include path (a80142b)
- Fixed include path for nlohmann lib (a4aa3d1)
- Versions now picked up from version.h (6460513)
- Fixed deprecated version of upload-artifact (cca220e)
- Fixed submodule checkout issue (68ceccf)
- Updated upload-artifact to v4 (a373ef8)
- Removed old ubuntu test build (01f8e6d)
- External code is now submodules. (593ef1b)
- Updated dependencies (45b097d)
- Workflow artifacts now save for three days only (eadcc40)
- Added log info (b4695c7)
- Now do proper join to worker threads on close (807ec65)
- Removed not needed driver info (9389586)
- Updated changelog (f3b63bd)
- Formatted (57de2e8)
- Added info about level II driver api (8ee29b6)
- Updated docs (60f7c60)
- Fixed format that should not be there (server settings in mqtt part of json) (35e0854)

## v15.0.0 - 2021-06-29

- Added switch to prevent abi warnings for nlohmann (07d9297)
- Fixed man install path (59dfc0d)
- Updated docs (ec702c2)
- Updated docs (5c98884)
- Added action workflow script (ae2fb88)
- Changed buildsystem to cmake (21502b6)
- Updated link (7fe3b20)
- Added resource folder (f3c1b0d)
- Now using VSCP standard function for sem wait (ddff65c)
- Fixed timeout bug (747f3ef)
- Added daemon debug config (2f47cf9)
- Added asan (fe2090f)
- Formatted (5f56921)
- Fixed topics (603dcf6)
- Now installing config file in make (1a3cb1a)
- Verified functionality (e57ab1d)
- Added man gitignore (e028ad2)
- Added sample confile into install (de380fe)
- Fixed debian install (5a257b3)
- Fixed some errors in the docs (df33193)
- Changed path to JSON parser (95be13a)
- Changed copytight year (4fa95ac)
- Adopted helper changes (0a05005)
- Save config added (9fb4c8e)
- Renamed remote variable constants (01b9b23)
- Interface changed to new standard interface (1be214a)
- Fixed debian package (61da20f)
- New structure transfered (dd5a114)
- Added submodule (0aadbe4)
- Transfered from main repository (2ce0919)
- Initial commit (a6dc67c)
