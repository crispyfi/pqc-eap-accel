"""EAP Acceleration proxy — bidirectional EAP-TLS fragment mediation.

The importable package backing the `eap-accel` command. Modules here are kept
straightforward and (for eap_tls.py) stdlib-only so the reassembly core ports
cleanly to C later. See CLAUDE.md for the design invariants.
"""

__version__ = "0.1.0"
