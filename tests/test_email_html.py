"""HTML email support: transports carry an HTML alternative, the shared shell
escapes what it's given, and plain-text-only messages stay exactly as before.
"""
import pathlib
import sys
from email.message import EmailMessage

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

import notify  # noqa: E402


def _plain():
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@x", "b@x", "s"
    m.set_content("hello")
    return m


def test_msg_parts_plain_message_has_no_html():
    frm, to, cc, subject, text, html = notify._msg_parts(_plain())
    assert text.strip() == "hello" and html is None


def test_msg_parts_extracts_the_html_alternative():
    m = _plain()
    notify.attach_html(m, "<p>rich</p>")
    frm, to, cc, subject, text, html = notify._msg_parts(m)
    assert text.strip() == "hello", "plain fallback must survive"
    assert html and "<p>rich</p>" in html


def test_attach_html_with_none_is_a_noop():
    m = notify.attach_html(_plain(), None)
    assert not m.is_multipart()


def test_html_shell_escapes_title_and_footer():
    out = notify.html_shell("<script>t</script>", "<p>body</p>", footer="<b>f</b>")
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "<b>f</b>" not in out and "&lt;b&gt;" in out
    assert "<p>body</p>" in out, "content is the caller's trusted HTML"


def test_severity_chip_colors_by_level():
    crit, low = notify.severity_chip("critical"), notify.severity_chip("low")
    assert "#dc2626" in crit and "CRITICAL" not in crit  # css uppercases, text stays as given
    assert crit != low
    assert "unknown" in notify.severity_chip("unknown")  # unknown levels degrade, not crash
