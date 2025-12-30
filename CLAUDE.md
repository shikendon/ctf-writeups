# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

CTF (Capture The Flag) writeups repository containing exploit code and solutions for security challenges.

## Directory Structure

Organized by platform and challenge:
```
{platform}/{challenge}/
├── README.md    # Challenge analysis, vulnerability explanation, exploitation strategy
└── exploit.py   # Working exploit script using pwntools
```

## Running Exploits

Exploits use pwntools and support local/remote modes:
```bash
python3 exploit.py           # Remote (default)
python3 exploit.py local     # Local testing with ./start binary
```

## Code Standards

- **Python**: PEP 8 - use `black . && isort .` before committing
- **Commit format**: Conventional Commits - `type(scope): description`
- **Comments**: English preferred, self-documenting code over redundant comments

## CONTRIBUTING.md Sync Requirement

Before any work, verify CONTRIBUTING.md matches source:
```bash
curl -s https://denpaio.github.io/CONTRIBUTING.md | diff CONTRIBUTING.md -
```
If outdated, update via PR first.
