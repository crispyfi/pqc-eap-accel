#!/usr/bin/env python3
"""Generate the results graph for README.md from the Test Results table.

Data is transcribed from the table in README.md (mean of 3 authentications).
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# (algorithm label, chain bytes, {rtt: {mode: wall_clock_ms}})
ALGOS = [
    ("rsa (2048)", 4242),
    ("falcon1024", 10293),
    ("mldsa65", 16753),
    ("mldsa87", 21987),
    ("sphincs128s", 26550),
]

# wall-clock (ms): algo -> rtt -> mode
WALL = {
    "rsa (2048)":   {20: (356, 202),   100: (1116, 559),  200: (1995, 949)},
    "falcon1024":   {20: (762, 301),   100: (2567, 618),  200: (4833, 1028)},
    "mldsa65":      {20: (1216, 468),  100: (3989, 960),  200: (7392, 1562)},
    "mldsa87":      {20: (1526, 545),  100: (5161, 989),  200: (9575, 1646)},
    "sphincs128s":  {20: (4277, 3073), 100: (8679, 3599), 200: (13962, 4172)},
}

RTTS = [20, 100, 200]
PASS_COLOR = "#c0392b"   # red - passthrough
REAS_COLOR = "#158c4c"   # green - reassemble (matches mermaid)

fig, axes = plt.subplots(1, 3, figsize=(15, 5.2), sharey=True)

labels = [a for a, _ in ALGOS]
x = range(len(labels))
width = 0.38

for ax, rtt in zip(axes, RTTS):
    passt = [WALL[a][rtt][0] / 1000 for a, _ in ALGOS]
    reas = [WALL[a][rtt][1] / 1000 for a, _ in ALGOS]
    b1 = ax.bar([i - width / 2 for i in x], passt, width,
                label="passthrough", color=PASS_COLOR)
    b2 = ax.bar([i + width / 2 for i in x], reas, width,
                label="reassemble", color=REAS_COLOR)
    ax.set_title(f"{rtt} ms RTT", fontweight="bold")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)
    for bars in (b1, b2):
        ax.bar_label(bars, fmt="%.1f", fontsize=7, padding=2)

axes[0].set_ylabel("Wall-clock authentication time (s)")
axes[1].set_xlabel("Certificate algorithm  (increasing chain size →)")
handles, lbls = axes[0].get_legend_handles_labels()
fig.legend(handles, lbls, loc="upper right", ncol=2, frameon=False)
fig.suptitle("EAP Acceleration: authentication time, passthrough vs reassemble",
             fontsize=14, fontweight="bold", x=0.5)
fig.tight_layout(rect=(0, 0, 1, 0.94))
fig.savefig("results/wallclock.png", dpi=130)
print("wrote results/wallclock.png")
