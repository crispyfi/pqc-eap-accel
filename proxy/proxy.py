"""
proxy.py — Top-level entry point for the EAP Acceleration proxy.

Loads config.yaml, builds the four pieces (SessionTable, UpstreamClient,
Mediator, DownstreamServer) and serves forever. All operator knobs live in
config.yaml — this file should not need to change across lab stages.

Run (installed as the `eap-accel` command by `uv sync`; see proxy/INSTALL.md):
    eap-accel                                         # uses config.yaml
    eap-accel path/to/cfg.yaml                        # custom path
    eap-accel --mode reassemble --fragment-size 1024 --framed-mtu 4000
    eap-accel --mode reassemble --strip-framed-mtu   # server's fragment_size only

Or directly during development, from the repo root:
    uv run eap-accel --mode passthrough

`eap-accel` runs from any directory (it's symlinked onto PATH) and needs no root
— the downstream RADIUS port (UDP/1812) is unprivileged. When no config path is
given and ./config.yaml isn't in the current directory, it falls back to the
config.yaml shipped beside this package (proxy/config.yaml).

Upstream latency is applied with netem at the kernel (the `latency` command /
latency.sh), not by this process — there's no latency flag.

CLI flags override the corresponding config.yaml values for a single run,
so a sweep script can vary one axis at a time without rewriting config.yaml
between cells. Values come from config.yaml unless explicitly overridden.
"""

import argparse
import logging
import os
import sys

import proxy.config as config
from proxy.session import SessionTable
from proxy.upstream_radius import UpstreamClient
from proxy.mediator import Mediator
from proxy.downstream_server import DownstreamServer
from proxy.report import Reporter


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EAP-TLS fragmentation proxy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "config", nargs="?", default="config.yaml",
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--mode", choices=("passthrough", "reassemble"), default=None,
        help="Override config.yaml `mode`",
    )
    parser.add_argument(
        "--fragment-size", type=int, default=None, dest="fragment_size",
        help="Override config.yaml `downstream.fragment_size` — the TLS-data "
             "budget per EAP-TLS packet sent toward the supplicant (AP-side "
             "fragmentation). Smaller values produce more fragments per "
             "auth, exercising the reassembly engine harder",
    )
    parser.add_argument(
        "--framed-mtu", type=int, default=None, dest="framed_mtu",
        help="Override config.yaml `upstream.framed_mtu` — the Framed-MTU "
             "value the proxy advertises to the auth server. Only honoured "
             "in reassemble mode (passthrough ignores it to avoid forwarding "
             "AP-undeliverable fragments)",
    )
    parser.add_argument(
        "--strip-framed-mtu", action="store_true", default=False,
        dest="strip_framed_mtu",
        help="Omit Framed-MTU from upstream Access-Requests entirely, so the "
             "auth server's own fragment size is the sole bound on upstream "
             "fragment length. Takes precedence over --framed-mtu / "
             "config.yaml `upstream.framed_mtu`; like them, honoured only in "
             "reassemble mode",
    )
    parser.add_argument(
        "--output", default=None, dest="output_dir", metavar="DIR",
        help="Directory for per-auth JSON records. Overrides config.yaml "
             "`output_dir`; defaults to proxy/output",
    )
    return parser.parse_args(argv[1:])


def _resolve_config(path: str) -> str:
    """Find the config file, tolerating being launched from any directory.

    If `path` exists relative to the current working directory, use it. Only
    when the operator didn't pass an explicit path (so `path` is the default
    "config.yaml") and it isn't in the CWD do we fall back to the config.yaml
    that ships next to this package — that's what makes `eap-accel` work when
    invoked via the /usr/local/bin symlink from an arbitrary directory. An
    explicit path that doesn't exist is left as-is so config.load raises a
    clear error pointing at exactly what the operator asked for.
    """
    if os.path.exists(path):
        return path
    if path == "config.yaml":
        pkg_default = os.path.join(os.path.dirname(__file__), "config.yaml")
        if os.path.exists(pkg_default):
            return pkg_default
    return path


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    cfg_path = _resolve_config(args.config)
    cfg = config.load(cfg_path)

    # Apply CLI overrides. Each is None if the operator didn't pass the flag,
    # in which case config.yaml's value stands.
    if args.mode is not None:
        cfg.mode = args.mode
    if args.fragment_size is not None:
        cfg.downstream.fragment_size = args.fragment_size
    # An explicit --framed-mtu asks for a specific advertised value, so it
    # clears a strip set in config.yaml; --strip-framed-mtu wins over a
    # framed_mtu that came from config.yaml (which ships one by default).
    if args.framed_mtu is not None:
        cfg.upstream.framed_mtu = args.framed_mtu
        cfg.upstream.strip_framed_mtu = False
    if args.strip_framed_mtu:
        cfg.upstream.strip_framed_mtu = True
    if args.output_dir is not None:
        cfg.output_dir = args.output_dir
    cfg.validate()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("proxy")
    log.info("config loaded from %s", os.path.abspath(cfg_path))
    log.info("starting in mode=%s downstream.fragment_size=%d "
             "upstream.framed_mtu=%s",
             cfg.mode,
             cfg.downstream.fragment_size,
             "stripped" if cfg.upstream.strip_framed_mtu
             else cfg.upstream.framed_mtu)
    if cfg.upstream.strip_framed_mtu and cfg.mode != "reassemble":
        log.warning("strip_framed_mtu is set but mode=%s — the AP's Framed-MTU "
                    "is forwarded verbatim (stripping applies to reassemble "
                    "mode only)", cfg.mode)
    log.info("downstream listen %s:%d  upstream %s:%d",
             cfg.downstream.listen_host, cfg.downstream.listen_port,
             cfg.upstream.host, cfg.upstream.port)

    sessions = SessionTable(
        mode=cfg.mode,
        upstream_fragment_size=cfg.upstream.fragment_size,
        downstream_fragment_size=cfg.downstream.fragment_size,
        max_message_len=cfg.max_message_len,
    )
    upstream = UpstreamClient(
        host=cfg.upstream.host,
        port=cfg.upstream.port,
        secret=cfg.upstream.shared_secret,
        framed_mtu_override=cfg.upstream.framed_mtu,
        strip_framed_mtu=cfg.upstream.strip_framed_mtu,
    )
    mediator = Mediator(upstream)
    reporter = Reporter(cfg.output_dir)
    log.info("per-auth JSON records -> %s", reporter.output_dir)
    server = DownstreamServer(
        listen_host=cfg.downstream.listen_host,
        listen_port=cfg.downstream.listen_port,
        shared_secret=cfg.downstream.shared_secret,
        mediator=mediator,
        upstream=upstream,
        sessions=sessions,
        reporter=reporter,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        return 0
    return 0


def main_cli() -> None:
    """Console-script entry point for the `eap-accel` command (see pyproject.toml).

    `[project.scripts]` needs a zero-argument callable, so this wraps main()
    with the process argv and turns its return code into the exit status.
    """
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
