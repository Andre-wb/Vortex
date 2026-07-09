"""
XSS-sink regression guard (security tripwire, not a behavioural test).

It freezes the currently-reviewed set of HTML-emitting code paths and the count
of inline event handlers in templates. When a change introduces a NEW raw-HTML
response, a NEW Jinja `| safe` filter, or NEW inline `on*=` handlers, one of
these tests FAILS — forcing a human to confirm the new sink is properly escaped
before it can land.

Why this matters here: the app's CSP keeps `script-src-attr 'unsafe-inline'`
(legacy inline handlers), so an *injected* inline handler would execute IF an
HTML-injection sink were ever introduced. Today no such sink exists (user data
flows through JSON APIs, uploads are force-downloaded, the one HTML page escapes
its fields). This guard keeps it that way.

If you intentionally add/remove a reviewed sink, update the matching baseline
below in the SAME commit.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_APP = _ROOT / "app"
_TEMPLATES = _ROOT / "templates"


# Any HTMLResponse(...) or Response(..., media_type="text/html"). Adding a new
# one requires review + html.escape(quote=True) on every interpolated value
# (or rendering via the autoescaped Jinja templates), then add it here.
_HTML_RESPONSE_BASELINE = {
    "chats/tipping.py",            # donate page — interpolated fields html.escape()'d
    "main.py",                     # cover/decoy page (static html string)
    "transport/cover_traffic.py",  # cover-traffic decoy page
}
_HTML_RESPONSE_RE = re.compile(r"""HTMLResponse\(|media_type\s*=\s*['"]text/html['"]""")


# Inline on*= handlers require `script-src-attr 'unsafe-inline'`. New ones widen
# that surface. This freezes the count so additions are caught; migrating a
# handler to addEventListener (in an external/nonce'd script) lets you lower it.
_INLINE_HANDLER_BASELINE = 819
_EVENTS = (
    "abort blur change click contextmenu copy cut dblclick drag drop error focus "
    "input keydown keypress keyup load mousedown mouseenter mouseleave mousemove "
    "mouseout mouseover mouseup paste scroll submit toggle touchend touchmove "
    "touchstart wheel animationend transitionend"
).split()
_ON_ATTR_RE = re.compile(r"\son(?:" + "|".join(_EVENTS) + r")\s*=", re.IGNORECASE)


_SAFE_FILTER_BASELINE = 0
_SAFE_FILTER_RE = re.compile(r"\|\s*safe\b")


def _py_files():
    return [p for p in _APP.rglob("*.py") if "/tests/" not in p.as_posix()]


def _template_files():
    return [p for p in _TEMPLATES.rglob("*.html") if not p.name.endswith(".bak")]


def test_no_new_html_response_sinks():
    found = set()
    for p in _py_files():
        text = p.read_text(encoding="utf-8", errors="ignore")
        if _HTML_RESPONSE_RE.search(text):
            found.add(p.relative_to(_APP).as_posix())

    new = found - _HTML_RESPONSE_BASELINE
    assert not new, (
        "New HTML-emitting code path(s): " + ", ".join(sorted(new)) + ". "
        "Raw HTML is an XSS sink — escape every interpolated value with "
        "html.escape(quote=True) (or use the autoescaped Jinja templates), then "
        "add the file to _HTML_RESPONSE_BASELINE in this test."
    )

    removed = _HTML_RESPONSE_BASELINE - found
    assert not removed, (
        "Baselined HTML sink(s) no longer present (moved/removed?): "
        + ", ".join(sorted(removed)) + ". Update _HTML_RESPONSE_BASELINE."
    )


def test_no_jinja_safe_filter():
    hits = []
    for p in _template_files():
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if _SAFE_FILTER_RE.search(line):
                hits.append(f"{p.relative_to(_TEMPLATES).as_posix()}:{i}")
    assert len(hits) <= _SAFE_FILTER_BASELINE, (
        "Jinja '| safe' disables autoescaping (XSS sink): " + ", ".join(hits) + ". "
        "Remove it or escape upstream; only bump _SAFE_FILTER_BASELINE after review."
    )


def test_inline_handler_count_not_increased():
    total = 0
    per_file = {}
    for p in _template_files():
        n = len(_ON_ATTR_RE.findall(p.read_text(encoding="utf-8", errors="ignore")))
        if n:
            per_file[p.relative_to(_TEMPLATES).as_posix()] = n
        total += n
    assert total <= _INLINE_HANDLER_BASELINE, (
        f"Inline event-handler count rose to {total} (baseline {_INLINE_HANDLER_BASELINE}). "
        "New inline on*= handlers widen the 'script-src-attr unsafe-inline' surface — "
        "prefer addEventListener in an external ('self'/nonce) script. "
        f"Per-file counts: {per_file}"
    )
