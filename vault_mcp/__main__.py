"""Run one worker; public ingress belongs behind Cloudflare Tunnel + Access."""
import os

import uvicorn

from .server import create_app

if os.geteuid() == 0:
    raise SystemExit("run the service as a nonroot UID")
os.umask(0o007)

uvicorn.run(create_app(), host="0.0.0.0", port=8000, access_log=False)
