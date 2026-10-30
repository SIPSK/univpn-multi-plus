"""Pure message codec derived from Windows UniVPN 10781.19.0.1214.

Evidence: local UniVPN.exe SHA256
24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1.
No sockets, processes, DLL loading, configuration, or credentials are retained.
This module encodes only observed layouts; it is not runtime validation.
See WINDOWS_PROTOCOL.md and ui-static/EVIDENCE.md for VAs and limits.
"""
from dataclasses import dataclass, field
import struct

HEADER = struct.Struct('!6I')
MAX_PAYLOAD = 1024 * 1024  # Local parser policy, not an inferred vendor limit.
LOGIN_PAYLOAD_SIZE = 0x7BC
FIRST_CONNECT_PAYLOAD_SIZE = 0x9D0
OTP_DATA_SIZE = 0x84
LINK_SELECT_PAYLOAD_SIZE = 0x88
AUTH_RESPONSE = struct.Struct('!7I2H')
FIRST_CONNECT_OK = 0x10000
LINK_SELECT_OK = 0x10004
AUTH_OK = 0x20000
SECOND_AUTH_REQUIRED = 0x3000A
CNEM_OK = 0x70000
CNEM_STOP_OK = 0x70003
LOGOUT_OK = 0xA0000

class CodecError(ValueError):
    pass

def _u32(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise CodecError('field must be an unsigned 32-bit integer')
    return value

def _fixed_bytes(value, capacity):
    if not isinstance(value, bytes) or b'\0' in value or len(value) >= capacity:
        raise CodecError('field must be NUL-free bytes below capacity')
    return value.ljust(capacity, b'\0')

def _utf8(value, capacity):
    if not isinstance(value, str):
        raise CodecError('field must be text')
    return _fixed_bytes(value.encode('utf-8'), capacity)

@dataclass(frozen=True)
class Message:
    source: int
    destination: int
    connection_type: int
    message_class: int
    opcode: int
    payload: bytes = field(default=b'', repr=False)

    def encode(self):
        if not isinstance(self.payload, bytes) or len(self.payload) > MAX_PAYLOAD:
            raise CodecError('invalid payload')
        values = tuple(_u32(v) for v in (self.source, self.destination,
                       self.connection_type, self.message_class, self.opcode))
        return HEADER.pack(*values, len(self.payload)) + self.payload

def decode_frame(frame):
    """Decode one complete in-memory frame; never reads a socket."""
    if not isinstance(frame, bytes) or len(frame) < HEADER.size:
        raise CodecError('incomplete header')
    words = HEADER.unpack_from(frame)
    if words[-1] > MAX_PAYLOAD or len(frame) != HEADER.size + words[-1]:
        raise CodecError('invalid frame length')
    return Message(*words[:-1], frame[HEADER.size:])

def csdk_registration(connection_type):
    """UniVPN.exe VA 0x4b16d3 / 0x4b178a. Merely returns bytes."""
    if type(connection_type) is not int or connection_type not in (1, 2):
        raise CodecError('connection_type must be 1 or 2')
    return Message(2, 4, connection_type, 1, 0x10006).encode()

def helper_start_registration(login_user_ansi, install_directory_ansi):
    """GUI VA 0x4b4669: char[32] + char[260], Windows ANSI bytes.

    This is a START request, not a status query. Helper VA 0x413ea0 may
    terminate an existing UniVPNCS.exe. This function performs no I/O.
    """
    body = (_fixed_bytes(login_user_ansi, 0x20)
            + _fixed_bytes(install_directory_ansi, 0x104))
    return Message(2, 1, 2, 1, 0x10006, body).encode()

def first_connect(raw_body):
    """Encode an explicitly prepared Windows FirstConnect body."""
    if not isinstance(raw_body, bytes) or len(raw_body) != FIRST_CONNECT_PAYLOAD_SIZE:
        raise CodecError('FirstConnect needs an independently verified 0x9D0-byte body')
    return Message(2, 4, 1, 1, 4, raw_body).encode()


def first_connect_body(endpoint, *, locale=0, sites=(), preference_enabled=0,
                       selected_index=0):
    """Build the Windows 0x9d0 body without reading an existing profile.

    GUI 0x418050, 0x418125-0x41821f, 0x4185de-0x41868f, 0x41a2f2.
    locale: Chinese 0 / English 1 (different from password-body locale).
    sites: explicit (host, port, proxy_flags) tuples, at most 16.
    A zeroed site structure occurs during GUI initialization at 0x418125,
    before entries are appended. It is not a usable connection request:
    backend 0x4ab3c0 rejects zero sites without attempting a gateway.
    A populated entry's third word is retained as an explicit input; it
    does not select the backend's separately loaded proxy configuration.
    """
    if type(locale) is not int or locale not in (0, 1):
        raise CodecError('locale must be Chinese 0 or English 1')
    if not isinstance(sites, (tuple, list)) or len(sites) > 16:
        raise CodecError('sites must contain at most 16 entries')
    if type(preference_enabled) is not int or preference_enabled not in (0, 1):
        raise CodecError('preference_enabled must be 0 or 1')
    if len(sites) <= 1 and preference_enabled:
        raise CodecError('Windows GUI disables auto-best for at most one site')
    if type(selected_index) is not int or not -1 <= selected_index < max(1, len(sites)):
        raise CodecError('selected index is outside the explicit site list')
    body = bytearray(FIRST_CONNECT_PAYLOAD_SIZE)
    struct.pack_into('<I', body, 0, locale)
    body[4:0x104] = _utf8(endpoint, 0x100)
    struct.pack_into('<I', body, 0x104, preference_enabled)
    for index, site in enumerate(sites):
        if not isinstance(site, (tuple, list)) or len(site) != 3:
            raise CodecError('site needs host, port, and explicit proxy flags')
        host, port, proxy_flags = site
        if type(port) is not int or not 1 <= port <= 65535:
            raise CodecError('site port must be between 1 and 65535')
        offset = 0x108 + index * 0x8c
        body[offset:offset + 0x80] = _utf8(host, 0x80)
        struct.pack_into('<II', body, offset + 0x80, port, _u32(proxy_flags))
    struct.pack_into('<Ii', body, 0x9c8, len(sites), selected_index)
    return bytes(body)


def first_connect_endpoint(endpoint, *, locale=0):
    """The GUI's minimal IPv4/domain host:port request, with one site.

    GUI0x4185de..0x418685 zeroes/appends the entry and disables auto-best
    when at most one site exists. Its copies are native LE. Receiver
    0x4aab60/0x4ab0e0 consumes explicit site host/port, never synthesizing
    a missing site from endpoint. Initial unused entry words remain zero.
    """
    if not isinstance(endpoint, str) or ':' not in endpoint:
        raise CodecError('endpoint needs an explicit host and port')
    host, port_text = endpoint.rsplit(':', 1)
    if (not host or any(char in host for char in '/\\@?#[]:')
            or any(ord(char) < 33 for char in host)
            or not port_text.isascii() or not port_text.isdigit()):
        raise CodecError('endpoint needs an IPv4/domain host and numeric port')
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise CodecError('endpoint port is outside the valid range')
    return first_connect(first_connect_body(endpoint, locale=locale,
                                            sites=((host, port, 0),),
                                            preference_enabled=0, selected_index=0))

def link_select(gateway, port, *, enable):
    """GUI VA 0x4b844c: native LE u32, UTF-8 char[128], native LE u32."""
    if type(enable) is not int or enable not in (0, 1):
        raise CodecError('enable must be 0 or 1')
    if type(port) is not int or not 1 <= port <= 65535:
        raise CodecError('port must be between 1 and 65535')
    body = struct.pack('<I', enable) + _utf8(gateway, 0x80) + struct.pack('<I', port)
    return Message(2, 4, 1, 1, 18, body).encode()

def password_login(endpoint, username, password, *, prefix_words):
    """Normal password path only; no inferred defaults for the five LE u32.

    GUI VA 0x480aa0 / 0x482410 / 0x4b51d0. Observed fields:
    endpoint@0x414[0x100], username@0x514[0x180], password@0x694[0x80].
    prefix_words[1] == 0 is the observed normal/password branch. Other
    authentication types need extra certificate fields and are unsupported.
    The first word's certificate semantics require receiver cross-validation.
    """
    if not isinstance(prefix_words, (tuple, list)) or len(prefix_words) != 5:
        raise CodecError('supply all five independently checked prefix words')
    words = tuple(_u32(v) for v in prefix_words)
    if words[1] != 0:
        raise CodecError('only the observed normal/password branch is supported')
    body = bytearray(LOGIN_PAYLOAD_SIZE)
    struct.pack_into('<5I', body, 0, *words)
    body[0x414:0x514] = _utf8(endpoint, 0x100)
    body[0x514:0x694] = _utf8(username, 0x180)
    body[0x694:0x714] = _utf8(password, 0x80)
    return Message(2, 4, 1, 3, 5, bytes(body)).encode()


def normal_password_login(endpoint, username, password, *, language=2):
    """Observed GUI normal-password path, with remember checkbox unchecked.

    DeviceCACheck 0x479ca0 writes first DWORD 0 on allowed continuation
    (0x479cc7 / 0x479e8e). This is NOT a promise to bypass/check TLS: the
    GUI also has a separate local certificate-warning dialog/cancel path.
    Remaining words: normal auth 0; unchecked remember 0; login type 1;
    language Chinese 2 / English 1. No user config is read or written here.
    """
    if type(language) is not int or language not in (1, 2):
        raise CodecError('language must be English 1 or Chinese 2')
    return password_login(endpoint, username, password,
                          prefix_words=(0, 0, 0, 1, language))


def saved_profile_login(endpoint, username, profile_name, *, language=2):
    """Reuse a native saved profile without reading/decrypting its password.

    CS0x4ae2a6 checks native LE word+8==1;0x4ae327 calls0x4278b0
    with profile name+0x734;0x4ae39d..0x4ae3e4 skips the clear function
    0x42c620 only for flag1. Supplied username must match the native
    decrypted profile, otherwise no saved password is used.
    GUI0x48397f..0x48399d copies UTF8 name at+0x734 with copy cap0x84;
    this builder conservatively reserves one NUL within those132 bytes.
    Path separators/control text are rejected; flag0/3 is never accepted.
    """
    if not isinstance(username, str) or not username:
        raise CodecError('saved profile needs a username')
    if not isinstance(profile_name, str) or not profile_name or profile_name in ('.', '..'):
        raise CodecError('saved profile name is invalid')
    if any(char in profile_name for char in ('/', '\\')) or any(ord(char) < 32 or ord(char) == 127 for char in profile_name):
        raise CodecError('saved profile name is invalid')
    if type(language) is not int or language not in (1, 2):
        raise CodecError('language must be English1 or Chinese2')
    frame = password_login(endpoint, username, '', prefix_words=(0, 0, 1, 1, language))
    body = bytearray(frame[HEADER.size:])
    body[0x734:0x7B8] = _utf8(profile_name, 0x84)
    return Message(2, 4, 1, 3, 5, bytes(body)).encode()

def dynamic_code(code):
    """GUI accepted-dialog path 0x47f1b6 and sender 0x4ba0af.

    Accepted dialog clears the 0x84-byte local struct, then copies at +4.
    Sender pads to 0x7BC payload, unlike the public Linux short OTP payload.
    The observed UI checks only nonempty text. Do not infer SMS or digits.
    """
    if not isinstance(code, str) or not code:
        raise CodecError('dynamic code must be nonempty text')
    body = bytearray(LOGIN_PAYLOAD_SIZE)
    body[4:0x84] = _utf8(code, 0x80)
    return Message(2, 4, 1, 3, 17, bytes(body)).encode()

def cnem_start(word0, word1, word2):
    """GUI VA 0x4b681d: three BE u32. Names/enum values not inferred here."""
    body = struct.pack('!3I', *(_u32(v) for v in (word0, word1, word2)))
    return Message(2, 4, 1, 5, 10, body).encode()


def tunnel_start(*, tunnel_mode=0, route_overwrite=0, gm_algorithm=0):
    """Windows CNEM start: reliable/fast/auto, route overwrite, GM toggle.

    0/1/2 tunnel modes are proven by UI 0x431c17-0x431d0d and
    0x43a28e/0x43a652/0x43ab10. The three BE values go to backend config
    IDs 0x12, 0x17, 0x18 in handler 0x4ae6c0, and are named by native
    CNEM initialization 0x4338f0. Ordinary default here is TCP, without
    overwriting an equal existing route, and non-GM algorithm.
    """
    if type(tunnel_mode) is not int or tunnel_mode not in (0, 1, 2):
        raise CodecError('tunnel_mode must be reliable 0, fast 1, or auto 2')
    if type(route_overwrite) is not int or route_overwrite not in (0, 1):
        raise CodecError('route_overwrite must be 0 or 1')
    if type(gm_algorithm) is not int or gm_algorithm not in (0, 1):
        raise CodecError('gm_algorithm must be 0 or 1')
    return cnem_start(tunnel_mode, route_overwrite, gm_algorithm)


def ssl_logout():
    """GUI 0x4b5978/0x4b59fb: class 3 / opcode 8 / empty payload.

    This only returns bytes. Sending it disconnects the owned backend.
    Never send to another GUI's active session.
    """
    return Message(2, 4, 1, 3, 8).encode()


def tunnel_stop():
    """GUI 0x4bb605: class5/op20 empty, success0x70003 at0x4bb72e."""
    return Message(2, 4, 1, 5, 20).encode()


def decode_auth_words(payload):
    """Decode only 32 fixed bytes, following GUI 0x4bc531..0x4bc761.

    Field names are deliberately not guessed. Values are 7 BE u32 and
    2 BE u16. The returned integers must not be treated as credentials or
    exported as raw response bodies. Additional trailing data is ignored.
    """
    if not isinstance(payload, bytes) or len(payload) < AUTH_RESPONSE.size:
        raise CodecError('auth response is shorter than its fixed layout')
    return AUTH_RESPONSE.unpack_from(payload)


def helper_port(message):
    """Decode helper response 0x10008 port without retaining other bytes."""
    if not isinstance(message, Message) or message.opcode != 0x10008:
        raise CodecError('unexpected helper response')
    if len(message.payload) < 4:
        raise CodecError('helper response has no port')
    port = struct.unpack_from('!I', message.payload)[0]
    if not 1 <= port <= 65535:
        raise CodecError('helper response port is invalid')
    return port


def safe_event(message):
    """Return only an allowlisted classification; never expose the payload.

    Operation success is meaningful only for a request this process owns
    and expected state, not proof by itself that a target is reachable.
    No undocumented async opcode is assigned a guessed meaning.
    """
    if not isinstance(message, Message):
        raise CodecError('event needs a decoded message')
    if message.opcode == SECOND_AUTH_REQUIRED:
        return {'status': 'second_auth', 'challengeType': 'dynamic_code'}
    if message.opcode == AUTH_OK:
        return auth_decision(message)
    if message.opcode == CNEM_OK:
        return {'status': 'connected'}
    return {'status': 'native_response', 'errorCode': message.opcode}


def first_connect_metadata(message):
    """Only four noncredential BE words from Windows FirstConnect reply.

    GUI0x4b7603..0x4b7727 converts body offsets0/4/8/12; static log labels
    are cauth type, verification, version MS, version LS. Their exact enum
    interpretation is NOT inferred. No server strings/config are returned.
    """
    if not isinstance(message, Message) or message.opcode != FIRST_CONNECT_OK:
        raise CodecError('not an ordinary FirstConnect success')
    if len(message.payload) < 16:
        raise CodecError('FirstConnect success has no fixed metadata')
    values = struct.unpack_from('!4I', message.payload)
    return dict(zip(('cauthType', 'verification', 'versionMs', 'versionLs'), values))


def auth_decision(message):
    """Classify normal password/dynamic-token results with native UI gates.

    GUI result map: 0x4b54c9 / 0x4b57b1, then 0x4848b2..
    0x4851a9. Success continues through 0x47dfe0 -> 0x47dd00,
    requiring host-check/cache-clear when fixed fields 4/5 are nonzero.
    Password expiry/modification branches use first u16 == 1; field6 is
    the modification capability, and may legitimately be 1 without expiry.
    This narrow adapter continues only first u16 == 0 and capability 0/1.
    Unknown outcomes return an opaque native error number, never payload.
    """
    if not isinstance(message, Message):
        raise CodecError('auth result needs a decoded message')
    if message.opcode == SECOND_AUTH_REQUIRED:
        return {'status': 'second_auth', 'challengeType': 'dynamic_code'}
    if message.opcode != AUTH_OK:
        return {'status': 'failed', 'errorCode': message.opcode}
    words = decode_auth_words(message.payload)
    if words[4] != 0 or words[5] != 0:
        return {'status': 'native_ui_required', 'errorCode': 'native_post_auth_policy'}
    if words[6] not in (0, 1) or words[7] != 0:
        return {'status': 'native_ui_required', 'errorCode': 'native_password_notice'}
    return {'status': 'authenticated'}


class FrameDecoder:
    """Bounded incremental byte parser for a caller-owned Windows channel."""
    __slots__ = ('_buffer',)

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, chunk):
        if not isinstance(chunk, bytes):
            raise CodecError('TCP input must be bytes')
        self._buffer.extend(chunk)
        messages = []
        while len(self._buffer) >= HEADER.size:
            payload_length = HEADER.unpack_from(self._buffer)[-1]
            if payload_length > MAX_PAYLOAD:
                self._buffer.clear()
                raise CodecError('native payload exceeds local size policy')
            length = HEADER.size + payload_length
            if len(self._buffer) < length:
                break
            frame = bytes(self._buffer[:length])
            del self._buffer[:length]
            messages.append(decode_frame(frame))
        return messages

    def close(self):
        """Drop buffered bytes; caller handles owned socket lifecycle."""
        self._buffer.clear()
