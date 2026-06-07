#!/usr/bin/env python3
"""Generate the 'why the patches' ceiling chart for README.md.

Two stacked panels sharing the algorithm x-axis:

  * top    - passthrough round-trips per auth vs the stock EAP/RADIUS
             round-trip caps the patches lift.
  * bottom - reassembled server/client flight bytes vs the stock RADIUS
             message / TLS record size ceilings the patches lift.

Stock ceiling values are taken verbatim from the diffs in patches/.
Per-algorithm figures are transcribed from results/ (mean of 3 auths);
they are structural (size / round-count) and so latency-independent.
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter

# (label, passthrough round-trips, server flight bytes, client flight bytes)
ALGOS = [
    ("rsa (2048)",  15,   4242,   3404),
    ("falcon512",   27,   6656,   5864),
    ("falcon1024",  41,  10294,   9502),
    ("mldsa44",     49,  12806,  11965),
    ("mldsa65",     65,  16753,  15955),
    ("mldsa87",     85,  21987,  21172),
    ("sphincs128s", 103, 26550,  25689),
    ("sphincs128f", 207, 54290,  52966),
    ("sphincs192f", 423, 110116, 109611),
]

# stock ceilings (see patches/)
FR_CAP   = 50      # FreeRADIUS per-session round-trip cap (rlm_eap/mem.c)
SUPP_CAP = 100     # wpa_supplicant EAP_MAX_AUTH_ROUNDS
RADIUS_MAX = 4096  # RADIUS message max (FreeRADIUS MAX_PACKET_LEN, radsecproxy)
EAPTLS_GUARD = 16384   # FreeRADIUS EAP-TLS reassembled-length guard (TLS 2^14)
TLS_RECORD = 65536     # supplicant TLS reassembly cap / FreeRADIUS MAX_RECORD_SIZE

SAFE, WARN, FAIL = "#158c4c", "#e67e22", "#c0392b"
SERVER_C, CLIENT_C = "#2166ac", "#67a9cf"

labels = [a[0] for a in ALGOS]
rounds = [a[1] for a in ALGOS]
server = [a[2] for a in ALGOS]
client = [a[3] for a in ALGOS]
x = range(len(labels))


def round_color(v):
    if v > SUPP_CAP:
        return FAIL
    if v > FR_CAP:
        return WARN
    return SAFE


fig, (top, bot) = plt.subplots(2, 1, figsize=(11, 9), sharex=True,
                               gridspec_kw={"height_ratios": [1, 1.15]})

# ---- top: round-trip ceilings ----------------------------------------
bars = top.bar(x, rounds, color=[round_color(v) for v in rounds], width=0.62)
top.bar_label(bars, fontsize=8, padding=2)
top.axhline(FR_CAP, ls="--", lw=1.6, color="#c0392b")
top.axhline(SUPP_CAP, ls="--", lw=1.6, color="#7d3c98")
top.text(-0.35, FR_CAP + 5, "FreeRADIUS round-trip cap = 50",
         ha="left", va="bottom", fontsize=8.5, color="#c0392b", fontweight="bold")
top.text(-0.35, SUPP_CAP + 5, "wpa_supplicant EAP_MAX_AUTH_ROUNDS = 100",
         ha="left", va="bottom", fontsize=8.5, color="#7d3c98", fontweight="bold")
top.set_ylim(0, 460)
top.set_ylabel("Round-trips per auth\n(passthrough)")
top.set_title("Round-trip ceilings — stock software aborts the auth above each line",
              fontweight="bold", fontsize=11)
top.grid(axis="y", alpha=0.3)
top.set_axisbelow(True)
top.legend(handles=[Patch(facecolor=SAFE, label="within stock round-trip caps"),
                    Patch(facecolor=WARN, label="exceeds FreeRADIUS cap (50)"),
                    Patch(facecolor=FAIL, label="exceeds supplicant cap (100) too")],
           loc="upper center", frameon=False, fontsize=8.5)

# ---- bottom: size ceilings -------------------------------------------
w = 0.38
b1 = bot.bar([i - w / 2 for i in x], server, w, label="server flight", color=SERVER_C)
b2 = bot.bar([i + w / 2 for i in x], client, w, label="client flight", color=CLIENT_C)
bot.set_yscale("log")
for ceil, col, txt in [
    (RADIUS_MAX,   "#c0392b", "RADIUS message max = 4096 B"),
    (EAPTLS_GUARD, "#e67e22", "FreeRADIUS EAP-TLS length guard = 16384 B"),
    (TLS_RECORD,   "#7d3c98", "TLS reassembly cap = 65536 B"),
]:
    bot.axhline(ceil, ls="--", lw=1.6, color=col)

bot.set_ylim(2500, 200000)
bot.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v/1000)}k" if v >= 1000 else int(v)))
bot.set_ylabel("Reassembled flight bytes\n(log scale)")
bot.set_title("Size ceilings — a single un-fragmented flight must fit under each line",
              fontweight="bold", fontsize=11)
bot.set_xticks(list(x))
bot.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
bot.set_xlabel("Certificate algorithm  (increasing chain size →)")
bot.grid(axis="y", alpha=0.3)
bot.set_axisbelow(True)
size_lines = [Line2D([0], [0], ls="--", lw=1.6, color=c, label=t) for c, t in [
    ("#c0392b", "RADIUS message max = 4096 B"),
    ("#e67e22", "FreeRADIUS EAP-TLS length guard = 16384 B"),
    ("#7d3c98", "TLS reassembly cap = 65536 B"),
]]
bot.legend(handles=[b1, b2, *size_lines], loc="upper left",
           frameon=False, fontsize=8.5, ncol=1)

fig.suptitle("Why the patches: stock EAP/RADIUS ceilings vs PQC certificate flights",
             fontsize=14, fontweight="bold")
fig.tight_layout(rect=(0, 0, 1, 0.97))
fig.savefig("results/ceilings.png", dpi=130)
print("wrote results/ceilings.png")
