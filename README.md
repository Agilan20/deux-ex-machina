# FalkorDB Graph Intelligence Platform

A Python application that connects to **FalkorDB** (a property graph database), verifies connectivity, and — in upcoming phases — feeds graph data to LLM models for agentic insights.

## Project Structure

```
weMakeDevs/
├── db/
│   ├── __init__.py
│   └── connection.py       # FalkorDB connection manager
├── verify_connection.py    # Phase 1 — connectivity verification
├── requirements.txt
├── .env.example
└── README.md
```

## Prerequisites

- Python 3.10+
- FalkorDB running on `localhost:6379`

Start FalkorDB with Docker (if not already running):
```bash
docker run --rm -p 6379:6379 falkordb/falkordb
```

## Setup

```bash
# 1. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env        # Windows
# cp .env.example .env        # macOS/Linux
# Edit .env if needed (default: localhost:6379, no password)
```

## Phase 1 — Verify Connectivity

```bash
python verify_connection.py
```

**What it checks:**

| Check | Description |
|-------|-------------|
| TCP connection | Raw socket reachability to `host:port` |
| PING / PONG | FalkorDB client handshake |
| Graph round-trip | `CREATE` a probe node → `MATCH` it back |
| Server info | Prints server version, OS, uptime |

## Roadmap

| Phase | Description |
|-------|-------------|
| ✅ Phase 1 | FalkorDB connectivity verification |
| 🔜 Phase 2 | Domain graph schema + seed data |
| 🔜 Phase 3 | LLM integration via API key (OpenAI / Gemini) |
| 🔜 Phase 4 | Agentic query loop (graph → LLM → insight) |
| 🔜 Phase 5 | REST API + visualization frontend |
