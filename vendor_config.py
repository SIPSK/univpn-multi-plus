"""Read only public network fields from legacy native GLOBAL profile INIs.

Observed Windows10781.19.0.1214 schema: GatewayAddress, GatewayPort,
Description. Public candidates never open sysconfig.ini/key.ini. The separate
private reference API requests four native INI metadata keys only; it never
requests ProfileInfo or key.ini, decrypts data, opens RPC, imports a profile,
or writes application state.
The index denotes the source native instance, not a new connection allocation.
Multiple candidates at one index must be resolved by the calling manager.
"""
from __future__ import annotations

import ipaddress
import hashlib
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

MAX_FILE_BYTES = 65536
NETWORK_KEYS = frozenset(('GatewayAddress', 'GatewayPort', 'Description'))
PRIVATE_KEYS = frozenset(('ProfileName', 'ProfileUser', 'LastLoginAddr', 'RemPwd'))


@dataclass(frozen=True, repr=False)
class SavedReference:
    """Local-only reference: contains no password or encrypted payload."""
    username: str
    profile_name: str

    def __repr__(self):
        return 'SavedReference(<private>)'


def _ordinary(path, *, directory):
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            return False
        return stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    except OSError:
        return False


def _text(raw):
    encodings = ('utf-16',) if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else ('utf-8-sig', 'gb18030')
    for encoding in encodings:
        try:
            decoded = raw.decode(encoding)
            if '\x00' not in decoded:
                return decoded
        except UnicodeError:
            pass
    return None


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    return value.strip()


def _gateway(value):
    if not value or len(value) > 253 or any(ord(char) < 33 for char in value):
        return None
    try:
        if '%' in value:
            return None
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            ascii_host = value.encode('idna').decode('ascii').lower()
        except UnicodeError:
            return None
        if ascii_host.endswith('.'):
            ascii_host = ascii_host[:-1]
        if not ascii_host or len(ascii_host) > 253:
            return None
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in ascii_host.split('.')):
            return None
        return ascii_host


def parse_network_profile(raw, index):
    """Parse a supplied byte fixture/file into one public candidate or None.

    Only values for the three exact schema keys in [GLOBAL] are extracted.
    Unknown lines, sections, account/password/key fields are never returned.
    No credential-specific schema or cipher compatibility is inferred.
    """
    if type(index) is not int or not 1 <= index <= 999:
        raise ValueError('native index is invalid')
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_FILE_BYTES:
        return None
    decoded = _text(raw)
    if decoded is None:
        return None
    inside = False
    seen_global = False
    fields = {}
    for line in decoded.splitlines():
        line = line.strip()
        if not line or line.startswith((';', '#')):
            continue
        if line.startswith('['):
            inside = line == '[GLOBAL]'
            if inside and seen_global:
                return None
            seen_global |= inside
            continue
        if not inside or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip()
        if key not in NETWORK_KEYS:
            continue
        if key in fields:
            return None
        fields[key] = _unquote(line.split('=', 1)[1])
    gateway = _gateway(fields.get('GatewayAddress', ''))
    port_text = fields.get('GatewayPort', '')
    if gateway is None or not re.fullmatch(r'[0-9]{1,5}', port_text):
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    name = fields.get('Description', '')
    if len(name) > 80 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        name = ''
    return {'gateway': gateway, 'port': port, 'name': name, 'index': index}


def load_candidates(appdata_root=None, *, indices=(1, 2)):
    """Backward-compatible public network-only candidates, one row per file.

    Description is preferred as the label; otherwise the original filename
    stem is retained. Distinct source files are not merged by endpoint/name.
    """
    return [{'gateway': row['gateway'], 'port': row['port'], 'name': row['name'],
             'index': row['sourceIndex']} for row in source_candidates(indices, appdata_root)]


def source_candidates(indexes, appdata=None):
    """Private source identity and public network metadata, one row per file.

    Source roots are APPDATA/UniVPN and APPDATA/UVPnnn. No recursive scan,
    sysconfig/key access, file values in errors, binding changes or writes.
    Each file is size bounded; no arbitrary count cap hides valid profiles.
    sourceId depends only on source index and exact filename, so Description
    edits preserve it; renaming a source file changes the source identity.
    sourceName is the filename stem; native cached ProfileName may differ.
    The caller chooses native slot allocation/serialization, never this parser.
    """
    indices = indexes
    if not isinstance(indices, (tuple, list)) or len(indices) > 999:
        raise ValueError('native indices are invalid')
    if any(type(index) is not int or not 1 <= index <= 999 for index in indices):
        raise ValueError('native index is invalid')
    root = Path(appdata) if appdata is not None else Path(os.environ.get('APPDATA', ''))
    if appdata is None and not os.environ.get('APPDATA'):
        return []
    if not _ordinary(root, directory=True):
        return []
    candidates = []
    for index in sorted(set(indices)):
        product = 'UniVPN' if index == 1 else f'UVP{index:03d}'
        product_dir = root / product
        config_dir = product_dir / 'config'
        if not _ordinary(product_dir, directory=True) or not _ordinary(config_dir, directory=True):
            continue
        try:
            files = sorted(config_dir.glob('*.ini'))
        except OSError:
            continue
        for file in files:
            if file.name.casefold() in ('key.ini', 'sysconfig.ini') or not _ordinary(file, directory=False):
                continue
            try:
                with file.open('rb') as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            candidate = parse_network_profile(data, index)
            del data
            if candidate is None:
                continue
            source_name = file.stem
            if not source_name or any(ord(char) < 32 or ord(char) == 127 for char in source_name):
                continue
            try:
                identity = (b'univpn-native-config-v1\0' + str(index).encode('ascii')
                            + b'\0' + file.name.encode('utf-8', errors='strict'))
            except UnicodeError:
                continue
            candidates.append({'sourceId': hashlib.sha256(identity).hexdigest()[:32],
                               'sourceIndex': index, 'sourceName': source_name,
                               'gateway': candidate['gateway'], 'port': candidate['port'],
                               'name': candidate['name'] or source_name})
    return candidates


def network_candidates(indexes, appdata=None):
    """Public network-only API. Does not choose/bind one of the candidates."""
    return load_candidates(appdata, indices=indexes)


def _private_ini_metadata(path):
    """Byte parser matching the vendor's byte-oriented INI schema.

    Section/key delimiters are located first. A value is sliced and retained
    only after its key passes the four-key allowlist. ProfileInfo lines are
    skipped without parsing/decoding their values; key.ini is never opened.
    No full-file text decoding or ACP/UTF8 guessing occurs here.
    """
    allowed = {key.encode('ascii') for key in PRIVATE_KEYS}
    metadata = {}
    section = None
    total = 0
    try:
        with path.open('rb') as stream:
            for line in stream:
                total += len(line)
                if total > MAX_FILE_BYTES or b'\x00' in line:
                    return {}
                line = line.strip()
                if not line or line.startswith((b';', b'#')):
                    continue
                if line.startswith(b'['):
                    match = re.fullmatch(rb'\[Session([0-9]{1,3})\]', line)
                    section = None
                    if match and int(match[1]) <= 127:
                        section = line[1:-1].decode('ascii')
                        if section in metadata:
                            return {}
                        metadata[section] = {}
                    continue
                if section is None:
                    continue
                separator = line.find(b'=')
                if separator < 0:
                    continue
                key = line[:separator].strip()
                if key not in allowed:
                    continue
                key = key.decode('ascii')
                if key in metadata[section]:
                    return {}
                value = line[separator + 1:].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in (34, 39):
                    value = value[1:-1]
                metadata[section][key] = value
    except OSError:
        return {}
    return metadata


def _private_ini_value(path, section, key, *, metadata=None):
    """Decode only a known metadata field using its proven native encoding."""
    if key not in PRIVATE_KEYS or not re.fullmatch(r'Session[0-9]{1,3}', section):
        return None
    metadata = _private_ini_metadata(path) if metadata is None else metadata
    value = metadata.get(section, {}).get(key)
    if not isinstance(value, bytes):
        return None
    try:
        # CS0x4279f0 converts incoming UTF8 profile-name to GBK before its
        # byte comparison with Session/ProfileName. Reverse that lookup key
        # exactly; never display it as the user's human-readable label.
        encoding = 'gbk' if key == 'ProfileName' else 'ascii'
        decoded = value.decode(encoding, errors='strict')
        if decoded.encode(encoding, errors='strict') != value:
            return None
        return decoded
    except UnicodeError:
        return None


def _saved_endpoint(address):
    # Only the bare host:port shape has been observed in this installed build.
    # URLs, host-only defaults, and other layouts require independent evidence.
    if not isinstance(address, str) or not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', address):
        return None
    host, port_text = address.rsplit(':', 1)
    host = _gateway(host)
    port = int(port_text)
    return (host, port) if host is not None and 1 <= port <= 65535 else None


def _source_profile_name_matches(raw_name, source_name):
    """Match a logical filename, without rewriting the native lookup bytes.

    Cache names can include the file's .ini extension. Only that appended
    extension is case insensitive; the filename stem stays exact. Matching
    UTF8 bytes does not change the proven GBK inverse mapping used on wire.
    """
    if not isinstance(raw_name, bytes):
        return False
    for encoding in ('gbk', 'utf-8'):
        try:
            stem = source_name.encode(encoding, errors='strict')
        except UnicodeError:
            continue
        if raw_name == stem or (raw_name[:-4] == stem and raw_name[-4:].lower() == b'.ini'):
            return True
    return False


def legacy_reference(profile, appdata=None, *, sourceName=None):
    """Return a unique matching saved-password reference, without its password.

    Native Windows evidence: Session0..127, RemPwd, LastLoginAddr,
    ProfileName and ProfileUser are ordinary INI metadata. The native login
    with flag1 resolves/decrypts ProfileInfo itself; this module never reads it.
    References remain local: never send them to logs, browser state or JSON.
    Unsupported encodings, unnamed users, unsaved/ambiguous references and
    unknown endpoint forms yield None, preserving existing manager bindings.
    ProfileName is the private GBK lookup key re-encoded as UTF8 by the wire
    builder; usernames are currently ASCII-only, without encoding guesses.
    With sourceName, raw metadata must match that logical filename stem or
    its full .ini filename, in GBK/UTF8 bytes. Only the appended extension's
    case is ignored. The exact native raw name is preserved through its GBK
    inverse mapping. It never falls back to an unrelated cached alias here.
    """
    if not isinstance(profile, dict):
        return None
    index = profile.get('index')
    if type(index) is not int or not 1 <= index <= 999:
        return None
    gateway = _gateway(profile.get('gateway', '')) if isinstance(profile.get('gateway'), str) else None
    port = profile.get('port')
    if gateway is None or type(port) is not int or not 1 <= port <= 65535:
        return None
    if sourceName is not None:
        if (not isinstance(sourceName, str) or not sourceName or sourceName in ('.', '..')
                or any(char in sourceName for char in ('/', '\\'))
                or any(ord(char) < 32 or ord(char) == 127 for char in sourceName)):
            return None
        try:
            if (sourceName.encode('gbk', errors='strict').decode('gbk', errors='strict') != sourceName
                    or len(sourceName.encode('utf-8', errors='strict')) >= 0x84):
                return None
        except UnicodeError:
            return None
    if appdata is None and not os.environ.get('APPDATA'):
        return None
    root = Path(appdata) if appdata is not None else Path(os.environ['APPDATA'])
    product = root / ('UniVPN' if index == 1 else f'UVP{index:03d}')
    config = product / 'sysconfig.ini'
    if not _ordinary(root, directory=True) or not _ordinary(product, directory=True) or not _ordinary(config, directory=False):
        return None
    try:
        if config.stat().st_size > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    metadata = _private_ini_metadata(config)
    matches = []
    matched_saved_count = 0
    for number in range(128):
        section = f'Session{number}'
        try:
            address = _private_ini_value(config, section, 'LastLoginAddr', metadata=metadata)
            if _saved_endpoint(address) != (gateway, port):
                continue
            profile_name = None
            if sourceName is not None:
                raw_name = metadata.get(section, {}).get('ProfileName')
                if not _source_profile_name_matches(raw_name, sourceName):
                    continue
            if _private_ini_value(config, section, 'RemPwd', metadata=metadata) != '1':
                continue
            matched_saved_count += 1
            if matched_saved_count > 1:
                return None
            if profile_name is None:
                profile_name = _private_ini_value(config, section, 'ProfileName', metadata=metadata)
            username = _private_ini_value(config, section, 'ProfileUser', metadata=metadata)
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(username, str) or not isinstance(profile_name, str) or not username or not profile_name:
            continue
        if not username.isascii():
            continue
        if len(username) > 255 or len(profile_name.encode('utf-8')) >= 0x84:
            continue
        if any(ord(char) < 32 or ord(char) == 127 for char in username + profile_name):
            continue
        if any(char in profile_name for char in ('/', '\\')) or profile_name in ('.', '..'):
            continue
        matches.append((username, profile_name))
    if len(matches) != 1:
        return None
    username, profile_name = matches[0]
    # The native lookup selects the first exact ProfileName across all saved
    # sessions and does not compare the cached gateway. Never let another
    # endpoint's same-name entry redirect which password the vendor selects.
    raw_name = profile_name.encode('gbk', errors='strict')
    if sum(values.get('ProfileName') == raw_name for values in metadata.values()) != 1:
        return None
    return SavedReference(username=username, profile_name=profile_name)
