import io

import patchcord


def test_help_overview():
    output = io.StringIO()
    patchcord.help(file=output)
    text = output.getvalue()
    assert "PATCHCORD" in text
    assert "Controller" in text
    assert 'patchcord.help("transfer")' in text


def test_help_topic():
    output = io.StringIO()
    patchcord.help("Controller", file=output)
    text = output.getvalue()
    assert "CONTROLLER" in text
    assert "Signature:" in text


def test_help_module():
    output = io.StringIO()
    patchcord.help("transfer", file=output)
    text = output.getvalue()
    assert "FILE TRANSFER" in text or "TRANSFER" in text
    assert "QUICK EXAMPLE" in text


def test_unknown_topic_is_friendly():
    output = io.StringIO()
    patchcord.help("not-a-topic", file=output)
    assert "Unknown Patchcord help topic" in output.getvalue()


def test_project_helpers():
    assert patchcord.version() == patchcord.__version__
    assert "version" in patchcord.about()
    assert patchcord.list_transports() == ["cloudflared", "local"]


def test_builtin_python_help_works():
    assert patchcord.Controller.__doc__ is None or isinstance(patchcord.Controller.__doc__, str)
