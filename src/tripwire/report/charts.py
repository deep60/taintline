"""Small, dependency-free SVG bar charts for findings write-ups.

Each bar is a rate k/n with its 95% Wilson interval drawn as a whisker, and the raw count printed
beside it, so a reader never sees a percentage without the sample size behind it. Labels are
escaped. Colours follow the viewer's light/dark preference (GitHub honours the media query in an
<img>-embedded SVG)."""
from __future__ import annotations

from html import escape

from ..scoring.asr import wilson

# one colour per series, picked to stay distinct in light and dark
_STYLE = """
<style>
  .bg{fill:#ffffff} .t{fill:#1f2328;font:600 15px system-ui,-apple-system,sans-serif}
  .l{fill:#1f2328;font:13px system-ui,-apple-system,sans-serif} .c{fill:#59636e;font:12px ui-monospace,monospace}
  .g{stroke:#d1d9e0} .w{stroke:#1f2328;stroke-width:1.4} .s0{fill:#2f6fde} .s1{fill:#d4762b} .s2{fill:#5b9a3e}
  @media (prefers-color-scheme: dark){
    .bg{fill:#0d1117} .t,.l{fill:#e6edf3} .c{fill:#9198a1} .g{stroke:#3d444d} .w{stroke:#e6edf3}
    .s0{fill:#5a93ef} .s1{fill:#e8924c} .s2{fill:#7bbd5b}
  }
</style>"""


def bar_chart(rows: list[tuple[str, list[tuple[int, int]]]], title: str, series: list[str] | None = None,
              note: str = "") -> str:
    """rows: [(label, [(k, n) per series])]. Returns an SVG document as a string."""
    series = series or [""]
    nser = len(series)
    if any(len(v) != nser for _, v in rows):
        raise ValueError("every row needs one (k, n) per series")
    label_w, plot_w, count_w = 230, 380, 110
    bar_h, gap = 14, 10
    top = 44 + (22 if nser > 1 else 0)
    row_h = nser * bar_h + gap
    height = top + len(rows) * row_h + 34 + (18 if note else 0)
    width = label_w + plot_w + count_w
    x0 = label_w
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" role="img" aria-label="{escape(title)}">', _STYLE,
           f'<rect class="bg" width="{width}" height="{height}"/>',
           f'<text class="t" x="12" y="24">{escape(title)}</text>']
    if nser > 1:                                   # legend
        lx = 12
        for i, name in enumerate(series):
            out.append(f'<rect class="s{i % 3}" x="{lx}" y="38" width="12" height="12"/>'
                       f'<text class="l" x="{lx + 17}" y="49">{escape(name)}</text>')
            lx += 30 + 8 * len(name)
    axis_y = top + len(rows) * row_h
    for pct in (0, 25, 50, 75, 100):              # gridlines
        gx = x0 + plot_w * pct / 100
        out.append(f'<line class="g" x1="{gx:.1f}" y1="{top - 6}" x2="{gx:.1f}" y2="{axis_y}"/>'
                   f'<text class="c" x="{gx:.1f}" y="{axis_y + 16}" text-anchor="middle">{pct}%</text>')
    for r, (label, vals) in enumerate(rows):
        y = top + r * row_h
        out.append(f'<text class="l" x="{x0 - 10}" y="{y + nser * bar_h / 2 + 4:.1f}" '
                   f'text-anchor="end">{escape(label)}</text>')
        for i, (k, n) in enumerate(vals):
            by = y + i * bar_h
            rate = k / n if n else 0.0
            lo, hi = wilson(k, n)
            bw = plot_w * rate
            out.append(f'<rect class="s{i % 3}" x="{x0}" y="{by + 2}" width="{bw:.1f}" height="{bar_h - 4}"/>')
            if n:
                mid = by + bar_h / 2
                wx1, wx2 = x0 + plot_w * lo, x0 + plot_w * hi
                out.append(f'<line class="w" x1="{wx1:.1f}" y1="{mid}" x2="{wx2:.1f}" y2="{mid}"/>'
                           f'<line class="w" x1="{wx1:.1f}" y1="{mid - 3}" x2="{wx1:.1f}" y2="{mid + 3}"/>'
                           f'<line class="w" x1="{wx2:.1f}" y1="{mid - 3}" x2="{wx2:.1f}" y2="{mid + 3}"/>')
            txt = f"{k}/{n}" if n else "n/a"
            out.append(f'<text class="c" x="{x0 + plot_w + 10}" y="{by + bar_h - 3}">{txt}</text>')
    foot = "Bars: rate. Whiskers: 95% Wilson interval."
    out.append(f'<text class="c" x="12" y="{axis_y + 34}">{escape(foot)}</text>')
    if note:
        out.append(f'<text class="c" x="12" y="{axis_y + 52}">{escape(note)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"
