import json
import os
import sys

from agentshield_intelligence.config import ConfigError, load_config
from agentshield_intelligence.server import serve


def main() -> int:
    try:
        config = load_config(os.environ)
    except ConfigError as exc:
        message = {"level": "error", "msg": "startup failed", "error": str(exc)}
        sys.stderr.write(json.dumps(message) + "\n")
        return 1
    serve(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
