# Non-SIEM Deployment Guide

This guide explains how to deploy JanuSec as a pre-SIEM triage layer. The instructions below are intentionally generic and omit any production secrets.

Prereqs:
- Python 3.10+
- Optional: Prometheus for metrics; if not installed the system uses no-op metric stubs
- LLM provider credentials (OpenAI/Anthropic/Ollama) if T1/T2 summaries are required

Minimal run (dev):

1. Install dependencies (virtualenv recommended)
2. Configure environment variables for demo mode (see sample-configs)
3. Start platform: `python run_platform.py` (demo mode)

Tiered storage, multi-tenant configs, and production hardening are described in `architecture-decisions.md`.
