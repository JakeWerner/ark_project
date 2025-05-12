# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (or will aim to).

## [0.5.0] - 2025-05-12 
This is the initial public-ready release of AutomatedReconKit (ARK), a Python library for Nmap automation.

### Added
- **Core Scanning Engine (`ARKEngine`):**
    - Orchestrates Nmap scans and processes results.
- **Nmap Handler (`NmapHandler`):**
    - Executes Nmap commands via subprocess and parses XML output.
    - Flexible Nmap executable path detection (explicit, `ARK_NMAP_PATH` env var, system PATH).
- **Structured Data Models (`autork.datamodels`):**
    - `Host`, `Port`, `Service`, `OSMatch` dataclasses for organized scan results.
- **Host Discovery:**
    - Ping scans (`-sn`).
    * Support for target input from files (`-iL` equivalent for ping scans).
    * Support for excluding targets via string or file (`--exclude`, `--excludefile` for ping scans).
- **TCP Port Scanning:**
    - Service and Version Detection (`-sV`).
    - Selectable TCP scan types (`-sS`, `-sT`, `-sF`, `-sX`, `-sN`, `-sA`).
    - Flexible port specification (top N, all ports).
- **UDP Port Scanning:**
    - UDP scans (`-sU`) with optional service/version detection (`-sV`).
    - Flexible port specification (top N UDP ports).
- **OS Detection:**
    - Integrated Nmap OS detection (`-O`).
- **NSE (Nmap Scripting Engine) Support:**
    - Flexible script selection using Nmap's `--script` syntax (categories, individual scripts, wildcards, directories).
    - Support for passing arguments to NSE scripts via `--script-args`.
    - Parsing of raw script output for both host-level and port-level scripts.
- **Scan Control:**
    - Nmap Timing Templates (`-T0` to `-T5`) for all scan types.
    - IPv6 Scanning Support (`-6`) for all scan types.
    * Nmap `--reason` flag support for detailed port state reasons.
- **Data Handling & Export:**
    - Export scan results (list of `Host` objects) to JSON format.
    - Export scan results to CSV format (one row per open/filtered port).
    - Save complete scan sessions to a JSON file.
    - Load scan sessions from a JSON file, reconstructing Python objects.
- **Logging:**
    - Internal logging using Python's `logging` module for operational messages, warnings, and errors.
- **Unit Testing:**
    - Comprehensive suite of unit tests (35+ tests) for `NmapHandler` and `ARKEngine` using `pytest` and `unittest.mock`, covering core logic, various Nmap flag combinations, and error handling.
- **Documentation:**
    - Initial `README.md` structure and content.
    - Docstrings for public classes and methods.

### Changed
- Internal `print` statements replaced with `logging`.
- Refined mock call assertions in unit tests for greater precision.

### Fixed
- Various bugs and inconsistencies identified during iterative development and testing.
- Corrected handling of Nmap command construction for different flag combinations.