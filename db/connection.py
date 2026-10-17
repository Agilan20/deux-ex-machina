"""
FalkorDB Connection Manager
---------------------------
Handles connection lifecycle to a FalkorDB instance.
Reads all config from environment variables (or .env file).

Supported env vars:
  FALKORDB_HOST      - hostname           (default: localhost)
  FALKORDB_PORT      - port               (default: 6379)
  FALKORDB_USERNAME  - ACL username       (required for FalkorDB Cloud)
  FALKORDB_PASSWORD  - password           (required for FalkorDB Cloud)
  FALKORDB_TLS       - 'true' for SSL/TLS (default: false)
"""

import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()


def get_client() -> FalkorDB:
    """
    Create and return an authenticated FalkorDB client.

    For FalkorDB Cloud you need:
      FALKORDB_HOST      = <cloud hostname>
      FALKORDB_PORT      = <cloud port>
      FALKORDB_USERNAME  = <username shown in the browser UI>
      FALKORDB_PASSWORD  = <your cloud password>
      FALKORDB_TLS       = false  (set true only if the endpoint requires it)
    """
    host     = os.getenv("FALKORDB_HOST", "localhost")
    port     = int(os.getenv("FALKORDB_PORT", 6379))
    username = os.getenv("FALKORDB_USERNAME", "").strip() or None
    password = os.getenv("FALKORDB_PASSWORD", "").strip() or None
    tls      = os.getenv("FALKORDB_TLS", "false").strip().lower() == "true"

    kwargs: dict = dict(host=host, port=port)

    if username:
        kwargs["username"] = username
    if password:
        kwargs["password"] = password
    if tls:
        kwargs["ssl"] = True

    return FalkorDB(**kwargs)
