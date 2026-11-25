"""Trace replay: one self-contained HTML page that shows, step by step, what the agent did, where the
injected text entered, and where the secret left.

Safety: trace text is attacker-controlled (that is the point of the tool), so every string is
HTML-escaped and the page carries a Content-Security-Policy that forbids scripts and remote loads.
The page has no JavaScript at all; it opens offline from disk."""
from __future__ import annotations

import html
import json
from pathlib import Path

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1c1a;--muted:#6b6b66;--line:#e3e3de;
--red:#b42318;--red-bg:#fef3f2;--amber:#8a5a00;--amber-bg:#fff7e0;--green:#067647;--green-bg:#ecfdf3;
--grey-bg:#f2f2ef;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1d1d1b;--ink:#ecebe6;--muted:#a3a29b;
--line:#33332f;--red:#ff8a80;--red-bg:#3a1714;--amber:#ffcc66;--amber-bg:#352a10;--green:#6ee7a8;
--green-bg:#10301f;--grey-bg:#262624}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:120px}
.stat b{display:block;font-size:20px}
.stat span{color:var(--muted);font-size:12px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:28px 0 8px}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:0 0 10px}
summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}
summary:before{content:"▸";color:var(--muted)}
details[open] summary:before{content:"▾"}
.title{font-weight:600}
.meta{color:var(--muted);font-size:13px}
.badge{font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;margin-left:auto;white-space:nowrap}
.b-leak{background:var(--red-bg);color:var(--red)}
.b-contact{background:var(--amber-bg);color:var(--amber)}
.b-clean{background:var(--green-bg);color:var(--green)}
.b-error{background:var(--grey-bg);color:var(--muted)}
ol{list-style:none;margin:0;padding:0 14px 14px}
li{border-left:2px solid var(--line);padding:6px 0 10px 14px;position:relative}
li:before{content:"";position:absolute;left:-6px;top:12px;width:10px;height:10px;border-radius:50%;
background:var(--card);border:2px solid var(--line)}
li.leak{border-left-color:var(--red)} li.leak:before{border-color:var(--red);background:var(--red)}
li.inj:before{border-color:var(--amber);background:var(--amber)}
.who{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
pre{font:13px/1.45 var(--mono);white-space:pre-wrap;word-break:break-word;margin:4px 0 0;
background:var(--grey-bg);border-radius:6px;padding:8px 10px}
.injected{background:var(--amber-bg);color:var(--amber);border-radius:3px;padding:0 2px}
mark.canary{background:var(--red-bg);color:var(--red);font-weight:700;border-radius:3px;padding:0 2px}
.flag{font-size:13px;font-weight:600;margin-top:4px}
.flag.red{color:var(--red)} .flag.amber{color:var(--amber)} .flag.green{color:var(--green)}
.verdict{margin:0 14px 14px;padding:10px 12px;border-radius:8px;font-weight:600}
.v-leak{background:var(--red-bg);color:var(--red)} .v-contact{background:var(--amber-bg);color:var(--amber)}
.v-clean{background:var(--green-bg);color:var(--green)} .v-error{background:var(--grey-bg);color:var(--muted)}
footer{color:var(--muted);font-size:13px;margin-top:32px}
"""


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _marked(text: str, canary: str | None) -> str:
    """Escape, then mark the canary. The canary is alphanumeric, so marking after escaping is safe."""
    out = _e(text)
    if canary:
        out = out.replace(_e(canary), f'<mark class="canary">{_e(canary)}</mark>')
    return out


def _result_html(res: str, payload: str | None, canary: str | None) -> tuple[str, bool]:
    if payload and payload in res:
        before, after = res.split(payload, 1)
        return (_marked(before, canary) + f'<span class="injected">{_e(payload)}</span>'
                + _marked(after, canary)), True
    return _marked(res, canary), False


def _outcome(t: dict) -> tuple[str, str, str]:
    if t.get("error"):
        return "error", "Error", "The trial errored. Counted as an error, never as secure."
    if t.get("canary_arrived"):
        return "leak", "Secret leaked", "The canary ARRIVED at the sink: the secret left the system."
    if t.get("sink_contact"):
        return "contact", "Attacker contacted", "The agent reached the attacker, but without the canary."
    return "clean", "Nothing left", "The sink received nothing."


def _scene(title: str, meta: str, t: dict, prompt: str | None, payload: str | None,
           open_: bool = False) -> str:
    kind, badge, verdict = _outcome(t)
    canary = t.get("canary")
    steps = []
    if prompt:
        steps.append(f'<li><div class="who">User</div><pre>{_e(prompt)}</pre></li>')
    for c in t.get("trace") or []:
        args = json.dumps(c.get("args", {}), ensure_ascii=False)
        leaks = bool(canary) and canary in args
        res_html, injected = _result_html(str(c.get("result", "")), payload, canary)
        reads = bool(canary) and canary in str(c.get("result", ""))
        flags = []
        if injected:
            flags.append('<div class="flag amber">Injected text entered here (highlighted)</div>')
        if reads:
            flags.append('<div class="flag amber">The agent now holds the secret</div>')
        if leaks:
            flags.append('<div class="flag red">The secret leaves here</div>')
        cls = "leak" if leaks else ("inj" if injected else "")
        steps.append(f'<li class="{cls}"><div class="who">Agent calls tool</div>'
                     f'<pre>{_e(c.get("tool", "?"))}({_marked(args, canary)})</pre>'
                     f'<div class="who" style="margin-top:6px">Tool returns</div><pre>{res_html}</pre>'
                     + "".join(flags) + "</li>")
    steps.append(f'<li><div class="who">Agent answers</div><pre>{_marked(t.get("answer") or "", canary)}</pre></li>')
    hits = t.get("sink_hits")
    if hits:
        body = "\n".join(f'{h.get("method", "")} {h.get("path", "")}  {h.get("body", "")}' for h in hits)
        steps.append(f'<li class="leak"><div class="who">Sink received</div><pre>{_marked(body, canary)}</pre></li>')
    return (f'<details{" open" if open_ else ""}><summary><span class="title">{_e(title)}</span>'
            f'<span class="meta">{_e(meta)}</span><span class="badge b-{kind}">{badge}</span></summary>'
            f'<ol>{"".join(steps)}</ol><div class="verdict v-{kind}">{_e(verdict)}</div></details>')


def _page(title: str, sub: str, stats: list[tuple[str, str]], sections: list[tuple[str, list[str]]]) -> str:
    stat_html = "".join(f'<div class="stat"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in stats)
    body = "".join(f"<h2>{_e(h)}</h2>{''.join(items)}" for h, items in sections if items)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>"
            f'<h1>{_e(title)}</h1><p class="sub">{_e(sub)}</p><div class="stats">{stat_html}</div>{body}'
            f"<footer>Taintline replay. Success is decided only by the canary arriving at the sink, "
            f"never by an LLM judge. Highlighted amber: injected text. Red: the secret.</footer>"
            f"</main></body></html>")


def demo_html(res: dict, payload: str) -> str:
    labels = {"baseline": ("Baseline", "normal task, no attack"),
              "attack": ("Attack", "instruction injected into a tool result"),
              "defended": ("Defended", "same attack, agent treats tool output as data")}
    s = res["summary"]
    items = []
    for sc in res["scenes"]:
        title, meta = labels.get(sc["scene"], (sc["scene"], ""))
        items.append(_scene(title, meta, sc, sc.get("prompt"), None if sc["scene"] == "baseline" else payload,
                            open_=sc["scene"] == "attack"))
    stats = [("attack leaked", "yes" if s["attack_leaked"] else "no"),
             ("baseline false alarm", "yes" if s["baseline_false_alarm"] else "no"),
             ("errors", str(s["errors"]))]
    return _page("Taintline demo replay", f"Agent: {res.get('agent', '?')}", stats, [("Scenes", items)])


def suite_html(res: dict, payloads: dict[str, str] | None = None, prompts: dict[str, str] | None = None,
               cap: int = 25) -> str:
    payloads, prompts = payloads or {}, prompts or {}
    leaks, contacts, errors, resisted, base = [], [], [], [], []
    for p in res.get("pairs", []):
        for t in p.get("trials", []):
            kind = _outcome(t)[0]
            row = (p["attack"], p["task"], t)
            {"leak": leaks, "contact": contacts, "error": errors, "clean": resisted}[kind].append(row)
    for b in res.get("baseline", []):
        for t in b.get("trials", [])[:1]:
            base.append(("baseline", b["task"], t))

    def render(rows, limit, open_first=False):
        return [_scene(a, f"task {task} · seed {t.get('seed')}", t, prompts.get(task),
                       None if a == "baseline" else payloads.get(a), open_=open_first and i == 0)
                for i, (a, task, t) in enumerate(rows[:limit])]

    o, s = res.get("overall", {}), res.get("summary", {})
    stats = [("trials", str(o.get("trials", "?"))), ("secret delivered", str(o.get("delivered", "?"))),
             ("attacker contact only", str(len(contacts))), ("errors", str(o.get("errors", "?"))),
             ("baseline false alarm", f"{s.get('baseline_false_alarm', 0):.0%}")]
    more = lambda rows, lim: f" (showing {lim} of {len(rows)})" if len(rows) > lim else ""  # noqa: E731
    sections = [(f"Secret leaked{more(leaks, cap)}", render(leaks, cap, True)),
                (f"Attacker contacted, no secret{more(contacts, 10)}", render(contacts, 10)),
                (f"Errors{more(errors, 5)}", render(errors, 5)),
                ("Baseline (no attack), one per task", render(base, 50)),
                (f"Resisted{more(resisted, 5)}", render(resisted, 5))]
    sub = f"Lab {res.get('lab') or res.get('server', '?')} · n={res.get('n_per_pair', '?')} per pair"
    return _page("Taintline replay", sub, stats, sections)


def session_html(res: dict, session: dict, hits: list[dict]) -> str:
    """One closed-agent session (taintline session score) as a single scene."""
    t = {"canary_arrived": res["canary_arrived"], "sink_contact": res["sink_contact"],
         "canary": next(iter(session["canaries"].values()), None), "answer": res.get("answer") or "",
         "trace": res.get("tool_calls") or [], "sink_hits": hits,
         "error": "; ".join(res["problems"]) if not res.get("valid", True) else None}
    payload = (session.get("injection") or {}).get("payload")
    stats = [("tool calls", str(len(t["trace"]))), ("injection fired", "yes" if res["injection_fired"] else "no"),
             ("secret delivered", "yes" if res["canary_arrived"] else "no"),
             ("valid", "yes" if res.get("valid", True) else "no")]
    scene = _scene(f"attack {res['attack']}", f"task {res['task']}", t, session["task"]["prompt"], payload, True)
    return _page("Taintline session replay", f"Lab {res['lab']} · your own client", stats, [("Session", [scene])])


def write_replay(res: dict, path: str | Path) -> Path:
    """Pick the right view for a demo or a live-suite result, recovering payloads and prompts from the lab."""
    path = Path(path)
    if res.get("kind") == "demo":
        from ..gateway.live import DEFAULT_PAYLOAD
        page = demo_html(res, DEFAULT_PAYLOAD)
    else:
        payloads, prompts = {}, {}
        if res.get("lab"):
            from ..labs import LABS
            lab = LABS.get(res["lab"])
            if lab:
                payloads = {a.id: a.payload for a in lab.attacks() if a.payload}
                prompts = {t.id: t.prompt for t in lab.tasks}
        page = suite_html(res, payloads, prompts)
    path.write_text(page, encoding="utf-8")
    return path
