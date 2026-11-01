from collections.abc import Mapping
from dataclasses import dataclass


class ConfigError(Exception):
    """Raised when the process configuration is missing or unsafe to run."""


@dataclass(frozen=True)
class Config:
    environment: str
    host: str
    port: int


def load_config(env: Mapping[str, str]) -> Config:
    environment = env.get("AGENTSHIELD_ENV", "") or "development"
    if environment == "production":
        raise ConfigError("production mode is refused until the intelligence engine is implemented")
    if environment not in {"development", "test"}:
        raise ConfigError("AGENTSHIELD_ENV is not supported")

    raw_addr = env.get("INTELLIGENCE_HTTP_ADDR", "") or "127.0.0.1:8082"
    host, port = _parse_addr(raw_addr)
    return Config(environment=environment, host=host, port=port)


def _parse_addr(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if separator == "" or host == "" or port_text == "":
        raise ConfigError("INTELLIGENCE_HTTP_ADDR must be host:port")
    if not port_text.isdigit():
        raise ConfigError("INTELLIGENCE_HTTP_ADDR port is invalid")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ConfigError("INTELLIGENCE_HTTP_ADDR port is invalid")
    return host, port
