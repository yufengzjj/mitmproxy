"""
Make upstream HTTP/2 connections match a browser profile from mytls (https://github.com/yufengzjj/mytls).

mytls is an optional dependency that is only imported when the `http2_fingerprint` option is set.
"""

import functools
from collections.abc import Iterator
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import h2.settings
import hpack

from ._http_h2 import BufferedH2Connection


@dataclass(frozen=True)
class Http2Fingerprint:
    settings: tuple[tuple[int, int], ...]
    """SETTINGS in wire order. Both which ids are present and their order are part of the fingerprint."""
    window_update: int
    """Connection-level WINDOW_UPDATE increment sent after the preface. 0 sends none."""
    pseudo_header_order: tuple[bytes, ...]
    priority: Mapping[str, Any]
    """
    Keyword arguments for `send_headers()` that every HEADERS frame gets.
    Empty forwards the priority of the client's HEADERS frame instead, or sends none if it had none.
    """
    encoder: type[hpack.Encoder]
    crumble_cookies: bool
    """Split `cookie` into one field per crumb, splitting on `;` and dropping one following space."""

    def apply(self, conn: BufferedH2Connection) -> None:
        """Replace the local settings and HPACK encoder. Must be called before `initiate_connection()`."""
        settings = _AdvertisedSettings(
            client=conn.config.client_side,
            initial_values=dict(self.settings),  # type: ignore[arg-type]
        )
        settings.advertised = tuple(setting for setting, _ in self.settings)
        conn.local_settings = settings
        # h2 updates the decoder only when a pending settings change is acknowledged,
        # and these values are not pending.
        conn.decoder.max_allowed_table_size = settings.header_table_size
        max_header_list_size = h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE
        if max_header_list_size in settings.advertised:
            conn.decoder.max_header_list_size = settings[max_header_list_size]
        conn.max_inbound_frame_size = max(
            conn.max_inbound_frame_size, settings.max_frame_size
        )
        conn.connection_window_increment = self.window_update
        conn.encoder = self.encoder()

    def format_headers(
        self, headers: list[tuple[bytes, bytes]]
    ) -> list[tuple[bytes, bytes]]:
        pseudo = [h for h in headers if h[0].startswith(b":")]
        pseudo.sort(key=self._pseudo_header_rank)
        fields = [h for h in headers if not h[0].startswith(b":")]
        if self.crumble_cookies:
            fields = list(_crumble_cookies(fields))
        return pseudo + fields

    def _pseudo_header_rank(self, header: tuple[bytes, bytes]) -> int:
        try:
            return self.pseudo_header_order.index(header[0])
        except ValueError:
            return len(self.pseudo_header_order)


class _AdvertisedSettings(h2.settings.Settings):
    """
    Settings whose SETTINGS frame lists only `advertised`, in that order.

    h2 builds the frame by iterating over the settings. Settings that are not advertised
    keep their RFC 9113 default, which is also what the peer assumes for them.
    """

    advertised: tuple[int, ...] = ()

    def __iter__(self) -> Iterator[int]:
        return iter(self.advertised)

    def __len__(self) -> int:
        return len(self.advertised)


def _crumble_cookies(
    headers: list[tuple[bytes, bytes]],
) -> Iterator[tuple[bytes, bytes]]:
    for name, value in headers:
        if name != b"cookie":
            yield name, value
            continue
        for i, crumb in enumerate(value.split(b";")):
            if i > 0 and crumb.startswith(b" "):
                crumb = crumb[1:]
            yield name, crumb


@functools.cache
def load(name: str) -> Http2Fingerprint:
    """Load a mytls browser profile by name. Raises ValueError if mytls is missing or the profile is unknown."""
    try:
        from mytls import browser_fp
    except ImportError as e:
        raise ValueError(f"HTTP/2 fingerprints require the mytls package: {e}") from e
    try:
        profile = browser_fp.profile(name)
    except LookupError as e:
        raise ValueError(str(e)) from e
    return Http2Fingerprint(
        settings=tuple(profile.settings),
        window_update=profile.window_update,
        pseudo_header_order=tuple(n.encode() for n in profile.pseudo_order),
        priority=profile.priority_for(),
        encoder=browser_fp._ENCODERS[profile.hpack],
        crumble_cookies=profile.hpack in ("quiche", "cfnetwork"),
    )
