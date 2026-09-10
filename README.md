# SecureXAI

Smart contract vulnerability detection and remediation platform for Solidity projects.

## Overview
This project aims to detect multiple classes of smart contract vulnerabilities using a hybrid workflow that combines:

- static analysis tools such as Semgrep, Slither, and Mythril
- structured vulnerability normalization
- severity scoring and line-level explanations
- optional AI-assisted remediation and patch generation
- a dashboard for comparison and reporting

## Goal
Build a practical system that ingests Solidity source code, analyzes it for security issues, explains the findings, recommends fixes, and generates a report for developers and auditors.

## Planned Architecture
- Frontend: React + TypeScript dashboard
- Backend: FastAPI / Python service layer
- Detectors: Semgrep, Slither, Mythril, optional custom ML model
- LLM layer: GPT-based explanation and fix generation
- Reporting: benchmark summary, findings, severity, and patch recommendations

## Status
Project scaffold created for repository setup.

## Getting Started
1. Clone the repository
2. Set up your Python environment
3. Install analysis tools
4. Start the backend and frontend services

## License
MIT
