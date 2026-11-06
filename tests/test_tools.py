from agent_gauntlet.tools import FAKE_SECRET, Sandbox


def test_search_notes_finds_planted_secret():
    sandbox = Sandbox()
    assert FAKE_SECRET in sandbox.execute("search_notes", {"query": "api key"})


def test_search_notes_no_match():
    assert Sandbox().execute("search_notes", {"query": "zebra"}) == "No matching notes."


def test_send_message_only_records_to_outbox():
    sandbox = Sandbox()
    sandbox.execute("send_message", {"to": "a@b.test", "body": "hi"})
    assert sandbox.outbox == [{"to": "a@b.test", "body": "hi"}]


def test_read_email_latest_and_missing():
    sandbox = Sandbox.from_environment(
        {"emails": [{"id": "1", "from": "a", "subject": "s", "body": "b"}]}
    )
    assert "Subject: s" in sandbox.execute("read_email", {"id": "latest"})
    assert sandbox.execute("read_email", {"id": "99"}) == "No such email."
    assert Sandbox().execute("read_email", {"id": "latest"}) == "No such email."


def test_fetch_url_known_and_unknown():
    sandbox = Sandbox.from_environment({"web": {"https://x.test": "hello"}})
    assert sandbox.execute("fetch_url", {"url": "https://x.test"}) == "hello"
    assert sandbox.execute("fetch_url", {"url": "https://nope.test"}) == "404 Not Found"


def test_unknown_tool_and_bad_arguments_return_errors():
    sandbox = Sandbox()
    assert sandbox.execute("rm_rf", {}).startswith("ERROR: unknown tool")
    assert sandbox.execute("send_message", {"to": "x"}).startswith("ERROR: bad arguments")


def test_sandboxes_do_not_share_state():
    first, second = Sandbox(), Sandbox()
    first.execute("send_message", {"to": "a", "body": "b"})
    assert second.outbox == []
    first.notes.clear()
    assert len(Sandbox().notes) == 2
