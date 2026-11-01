SERVICE = "intelligence-engine"
VERSION = "0.1.0"


def live_body() -> dict[str, object]:
    return {
        "status": "ok",
        "service": SERVICE,
        "version": VERSION,
        "checks": {"process": "ok", "analysis": "not_implemented"},
    }


def ready_body() -> dict[str, object]:
    return {
        "status": "not_ready",
        "service": SERVICE,
        "version": VERSION,
        "reason": "content analysis is not implemented",
        "checks": {"process": "ok", "analysis": "not_implemented"},
    }


def dispatch(method: str, target: str) -> tuple[int, dict[str, object]]:
    path = target.split("?", 1)[0]
    if method != "GET":
        return 404, {"error": {"code": "not_found", "message": "not found"}}
    if path == "/health/live":
        return 200, live_body()
    if path == "/health/ready":
        return 503, ready_body()
    return 404, {"error": {"code": "not_found", "message": "not found"}}
