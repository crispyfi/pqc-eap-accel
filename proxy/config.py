"""
config.py — Operator configuration for the EAP-TLS fragmentation proxy.
"""

import os
from dataclasses import dataclass
import yaml

# Default output location: proxy/output (beside this package), so per-auth JSON
# records land in one canonical place regardless of the directory eap-accel is
# launched from. Override in config.yaml (output_dir:) or with --output.
_DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


@dataclass
class DownstreamConfig:
    """The NAS facing RADIUS server leg."""
    listen_host: str           # usually 0.0.0.0
    listen_port: int           # 1812
    shared_secret: str         # shared with the AP (NAS)
    fragment_size: int         # TLS-data budget per packet toward the supplicant


@dataclass
class UpstreamConfig:
    """The auth-server-facing leg. Plain RADIUS/UDP to a local radsecproxy
    instance, which owns the RadSec/TLS transport and cert trust."""
    host: str
    port: int
    shared_secret: str
    fragment_size: int
    framed_mtu: int | None = None

@dataclass
class Config:
    mode: str
    max_message_len: int
    output_dir: str            # dir for per-auth JSON records (one file per auth)
    downstream: DownstreamConfig
    upstream: UpstreamConfig

    def validate(self) -> None:
        if self.mode not in ("reassemble", "passthrough"):
            raise ValueError(f"mode must be reassemble|passthrough, got {self.mode!r}")
        if not (1 <= self.downstream.fragment_size <= 65000):
            raise ValueError("downstream.fragment_size out of range")
        if not (1 <= self.upstream.fragment_size <= 65000):
            raise ValueError("upstream.fragment_size out of range")
        if self.upstream.framed_mtu is not None and not (1 <= self.upstream.framed_mtu <= 65000):
            raise ValueError("upstream.framed_mtu out of range")
        if self.max_message_len < 4096:
            raise ValueError("max_message_len too small for any real cert chain")


def load(path: str) -> Config:
    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    cfg = Config(
        mode=raw["mode"],
        max_message_len=int(raw.get("max_message_len", 262144)),
        output_dir=raw.get("output_dir") or _DEFAULT_OUTPUT_DIR,
        downstream=DownstreamConfig(**raw["downstream"]),
        upstream=UpstreamConfig(**raw["upstream"]),
    )
    cfg.validate()
    return cfg
