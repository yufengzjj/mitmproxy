import sys
import types

import h2.config
import h2.settings
import hpack
import hyperframe.frame
import pytest

from mitmproxy.connection import Server
from mitmproxy.http import HTTPFlow
from mitmproxy.proxy.commands import OpenConnection
from mitmproxy.proxy.commands import SendData
from mitmproxy.proxy.events import DataReceived
from mitmproxy.proxy.layers import http
from mitmproxy.proxy.layers.http._http2_fingerprint import Http2Fingerprint
from mitmproxy.proxy.layers.http._http2_fingerprint import load
from mitmproxy.proxy.layers.http._http_h2 import BufferedH2Connection
from test.mitmproxy.proxy.layers.http.test_http2 import decode_frames
from test.mitmproxy.proxy.layers.http.test_http2 import make_h2
from test.mitmproxy.proxy.layers.http.test_http2 import start_h2_client
from test.mitmproxy.proxy.tutils import Placeholder
from test.mitmproxy.proxy.tutils import reply

CHROME_SETTINGS = [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
CHROME_PRIORITY = {
    "priority_exclusive": True,
    "priority_depends_on": 0,
    "priority_weight": 256,
}


class FakeEncoder(hpack.Encoder):
    pass


class FakeProfile:
    settings = CHROME_SETTINGS
    window_update = 15663105
    pseudo_order = (":method", ":authority", ":scheme", ":path")
    hpack = "quiche"

    def priority_for(self):
        return dict(CHROME_PRIORITY)


class FakeForwardingProfile(FakeProfile):
    def priority_for(self):
        return {}


@pytest.fixture
def fake_mytls(monkeypatch):
    def profile(name):
        if name == "chrome":
            return FakeProfile()
        if name == "forwarding":
            return FakeForwardingProfile()
        raise LookupError(f"unknown brand {name!r}")

    browser_fp = types.ModuleType("mytls.browser_fp")
    browser_fp.profile = profile
    browser_fp._ENCODERS = {"quiche": FakeEncoder}
    mytls = types.ModuleType("mytls")
    mytls.browser_fp = browser_fp
    monkeypatch.setitem(sys.modules, "mytls", mytls)
    monkeypatch.setitem(sys.modules, "mytls.browser_fp", browser_fp)
    load.cache_clear()
    yield
    load.cache_clear()


def make_fingerprint(**kwargs) -> Http2Fingerprint:
    return Http2Fingerprint(
        **{
            "settings": tuple(CHROME_SETTINGS),
            "window_update": 15663105,
            "pseudo_header_order": (b":method", b":authority", b":scheme", b":path"),
            "priority": {},
            "encoder": FakeEncoder,
            "crumble_cookies": False,
            **kwargs,
        }
    )


def test_load(fake_mytls):
    assert load("chrome") == make_fingerprint(
        priority=CHROME_PRIORITY, crumble_cookies=True
    )
    with pytest.raises(ValueError, match="unknown brand"):
        load("netscape")


def test_load_without_mytls(monkeypatch):
    monkeypatch.setitem(sys.modules, "mytls", None)
    with pytest.raises(ValueError, match="require the mytls package"):
        load("chrome")


def test_apply():
    conn = BufferedH2Connection(h2.config.H2Configuration(client_side=True))
    make_fingerprint().apply(conn)
    conn.initiate_connection()

    settings, window_update = decode_frames(conn.data_to_send())
    assert isinstance(settings, hyperframe.frame.SettingsFrame)
    assert list(settings.settings.items()) == CHROME_SETTINGS
    assert isinstance(window_update, hyperframe.frame.WindowUpdateFrame)
    assert window_update.window_increment == 15663105

    assert len(conn.local_settings) == 4
    assert conn.local_settings.initial_window_size == 6291456
    assert conn.local_settings.max_frame_size == 16384
    assert conn.decoder.max_allowed_table_size == 65536
    assert conn.decoder.max_header_list_size == 262144
    assert isinstance(conn.encoder, FakeEncoder)


def test_apply_minimal():
    conn = BufferedH2Connection(h2.config.H2Configuration(client_side=True))
    default_header_list_size = conn.decoder.max_header_list_size
    make_fingerprint(
        settings=((h2.settings.SettingCodes.MAX_FRAME_SIZE, 2**20),), window_update=0
    ).apply(conn)
    conn.initiate_connection()

    (settings,) = decode_frames(conn.data_to_send())
    assert list(settings.settings.items()) == [(5, 2**20)]
    assert conn.max_inbound_frame_size == 2**20
    assert conn.decoder.max_header_list_size == default_header_list_size


def test_format_headers():
    headers = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b":protocol", b"websocket"),
        (b":authority", b"example.com"),
        (b"cookie", b"a=1; b=2;c=3"),
        (b"accept", b"*/*"),
    ]
    assert make_fingerprint().format_headers(headers) == [
        (b":method", b"GET"),
        (b":authority", b"example.com"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b":protocol", b"websocket"),
        (b"cookie", b"a=1; b=2;c=3"),
        (b"accept", b"*/*"),
    ]
    assert make_fingerprint(crumble_cookies=True).format_headers(headers)[5:] == [
        (b"cookie", b"a=1"),
        (b"cookie", b"b=2"),
        (b"cookie", b"c=3"),
        (b"accept", b"*/*"),
    ]


def test_http2_client(tctx, fake_mytls):
    tctx.options.http2_fingerprint = "chrome"
    playbook, cff = start_h2_client(tctx)
    flow = Placeholder(HTTPFlow)
    server = Placeholder(Server)
    initial = Placeholder(bytes)
    assert (
        playbook
        >> DataReceived(
            tctx.client,
            cff.build_headers_frame(
                (
                    (b":method", b"GET"),
                    (b":scheme", b"http"),
                    (b":path", b"/"),
                    (b":authority", b"example.com"),
                    (b"cookie", b"a=1; b=2"),
                ),
                flags=["END_STREAM"],
            ).serialize(),
        )
        << http.HttpRequestHeadersHook(flow)
        >> reply()
        << http.HttpRequestHook(flow)
        >> reply()
        << OpenConnection(server)
        >> reply(None, side_effect=make_h2)
        << SendData(server, initial)
    )
    settings, window_update, headers = decode_frames(initial())
    assert list(settings.settings.items()) == CHROME_SETTINGS
    assert window_update.window_increment == 15663105
    assert isinstance(headers, hyperframe.frame.HeadersFrame)
    assert "PRIORITY" in headers.flags
    assert headers.exclusive
    assert headers.stream_weight == 255
    assert hpack.Decoder().decode(headers.data, True) == [
        (b":method", b"GET"),
        (b":authority", b"example.com"),
        (b":scheme", b"http"),
        (b":path", b"/"),
        (b"cookie", b"a=1"),
        (b"cookie", b"b=2"),
    ]


REQUEST = (
    (b":method", b"GET"),
    (b":scheme", b"http"),
    (b":path", b"/"),
    (b":authority", b"example.com"),
)


def test_http2_client_forwards_priority(tctx, fake_mytls):
    tctx.options.http2_fingerprint = "forwarding"
    playbook, cff = start_h2_client(tctx)
    flow1 = Placeholder(HTTPFlow)
    flow2 = Placeholder(HTTPFlow)
    flow3 = Placeholder(HTTPFlow)
    server = Placeholder(Server)
    initial = Placeholder(bytes)
    second = Placeholder(bytes)
    third = Placeholder(bytes)
    assert (
        playbook
        >> DataReceived(
            tctx.client,
            cff.build_headers_frame(
                REQUEST,
                flags=["END_STREAM", "PRIORITY"],
                stream_id=1,
                exclusive=True,
                depends_on=0,
                stream_weight=219,
            ).serialize(),
        )
        << http.HttpRequestHeadersHook(flow1)
        >> reply()
        << http.HttpRequestHook(flow1)
        >> reply()
        << OpenConnection(server)
        >> reply(None, side_effect=make_h2)
        << SendData(server, initial)
        >> DataReceived(
            tctx.client,
            cff.build_headers_frame(
                REQUEST,
                flags=["END_STREAM", "PRIORITY"],
                stream_id=3,
                exclusive=False,
                depends_on=1,
                stream_weight=99,
            ).serialize(),
        )
        << http.HttpRequestHeadersHook(flow2)
        >> reply()
        << http.HttpRequestHook(flow2)
        >> reply()
        << SendData(server, second)
        >> DataReceived(
            tctx.client,
            cff.build_headers_frame(
                REQUEST,
                flags=["END_STREAM", "PRIORITY"],
                stream_id=5,
                exclusive=False,
                depends_on=7,
                stream_weight=15,
            ).serialize(),
        )
        << http.HttpRequestHeadersHook(flow3)
        >> reply()
        << http.HttpRequestHook(flow3)
        >> reply()
        << SendData(server, third)
    )
    *_, headers = decode_frames(initial())
    assert "PRIORITY" in headers.flags
    assert (headers.exclusive, headers.depends_on, headers.stream_weight) == (
        True,
        0,
        219,
    )
    (headers,) = decode_frames(second())
    assert (headers.exclusive, headers.depends_on, headers.stream_weight) == (
        False,
        1,
        99,
    )
    # stream 7 has no stream on the server connection, so the request depends on the root.
    (headers,) = decode_frames(third())
    assert (headers.exclusive, headers.depends_on, headers.stream_weight) == (
        False,
        0,
        15,
    )


def test_http2_client_without_client_priority(tctx, fake_mytls):
    tctx.options.http2_fingerprint = "forwarding"
    playbook, cff = start_h2_client(tctx)
    flow = Placeholder(HTTPFlow)
    server = Placeholder(Server)
    initial = Placeholder(bytes)
    assert (
        playbook
        >> DataReceived(
            tctx.client,
            cff.build_headers_frame(REQUEST, flags=["END_STREAM"]).serialize(),
        )
        << http.HttpRequestHeadersHook(flow)
        >> reply()
        << http.HttpRequestHook(flow)
        >> reply()
        << OpenConnection(server)
        >> reply(None, side_effect=make_h2)
        << SendData(server, initial)
    )
    *_, headers = decode_frames(initial())
    assert isinstance(headers, hyperframe.frame.HeadersFrame)
    assert "PRIORITY" not in headers.flags
