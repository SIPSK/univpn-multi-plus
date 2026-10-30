"""Owned Windows UniVPN session; no configuration, subprocesses, or credential logs.

Only NativeEnvironment may authorize/prepare the particular installed instance.
The transport connects exclusively to the loopback port that prepare returns.
The module never attaches to an existing GUI, discovers ports, or restarts a
backend on failure. See research/WINDOWS_PROTOCOL.md for fixed Windows ABI.
"""
from __future__ import annotations

from collections import deque
import socket
import sys
import threading
import time

import windows_messages as wire


class SessionError(RuntimeError):
    """A fixed, public-safe error. Never construct from native exception text."""


class _Cancelled(Exception):
    pass


def _wipe(value):
    if isinstance(value, bytearray):
        value[:] = bytes(len(value))


class _Channel:
    """A single private socket and bounded framing buffer, owned by one reader."""

    def __init__(self, sock):
        self.socket = sock
        self.decoder = wire.FrameDecoder()
        self.pending = deque()

    def close(self):
        self.decoder.close()
        self.pending.clear()
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()


class WindowsSession:
    CONNECT_TIMEOUT = 12.0
    FIRST_TIMEOUT = 40.0
    AUTH_TIMEOUT = 90.0
    TUNNEL_TIMEOUT = 90.0
    OTP_TIMEOUT = 300.0
    TARGET_WAIT_TIMEOUT = 10.0
    CLEANUP_TIMEOUT = 2.0

    def __init__(self, profile, on_event, environment):
        if not isinstance(profile, dict) or not callable(on_event):
            raise SessionError('连接配置无效')
        self.profile = dict(profile)
        self.on_event = on_event
        self.environment = environment
        self._condition = threading.Condition(threading.RLock())
        self._stop = threading.Event()
        self._done = threading.Event()
        self._async_failed = threading.Event()
        self._status = {'status': 'disconnected'}
        self._started = False
        self._worker = None
        self._event_worker = None
        self._sync = None
        self._events = None
        self._helper = None
        self._owned = False
        self._cleanup_confirmed = None
        self._login_sent = False
        self._tunnel_requested = False
        self._otp_frame = None
        self._phase = 'idle'

    def status_snapshot(self):
        with self._condition:
            return dict(self._status)

    def start(self, username, password):
        """Return immediately; prepare, bootstrap and authentication run in a worker.

        A session object starts once. Explicit user retry creates a new object;
        this object never automatically reboots or resends a password.
        """
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise SessionError('请输入账号和密码')
        endpoint = self._endpoint()
        try:
            login_frame = bytearray(wire.normal_password_login(endpoint, username, password))
        except (wire.CodecError, UnicodeError):
            raise SessionError('账号或密码长度不符合客户端要求') from None
        self._start_frame(login_frame)

    def start_saved(self, username, profile_name):
        """Explicit native saved-profile login; no password is requested/read.

        The caller privately resolves the existing native reference. This
        method never scans files, reads key.ini/ProfileInfo, decrypts, or
        migrates credentials into Python or a vault. Dynamic-code handling
        and ownership/policy gates are identical to a normal user login.
        """
        try:
            login_frame = bytearray(wire.saved_profile_login(self._endpoint(), username, profile_name))
        except (wire.CodecError, UnicodeError):
            raise SessionError('旧连接的保存信息格式不受支持') from None
        self._start_frame(login_frame)

    def _start_frame(self, login_frame):
        with self._condition:
            if self._stop.is_set() or self._done.is_set():
                _wipe(login_frame)
                raise SessionError('此连接已经结束，请重新发起连接')
            if self._started:
                _wipe(login_frame)
                raise SessionError('当前连接已经开始，请先断开')
            self._started = True
            self._status = {'status': 'authenticating'}
            self._worker = threading.Thread(target=self._run, args=(login_frame,),
                                            name='UniVPN-owned-session', daemon=True)
        self._publish({'status': 'authenticating'})
        with self._condition:
            # Publishing may yield to a concurrent disconnect. An unstarted
            # thread is not joinable and must never be launched after cancel.
            if self._stop.is_set() or self._done.is_set():
                _wipe(login_frame)
                raise SessionError('此连接已经结束，请重新发起连接')
            try:
                self._worker.start()
            except RuntimeError:
                _wipe(login_frame)
                self._done.set()
                self._publish({'status': 'error', 'error': '无法启动原生连接任务'})
                raise SessionError('无法启动原生连接任务') from None

    def submit_otp(self, code):
        """Queue one explicit code for the existing challenge; never resends it."""
        try:
            frame = bytearray(wire.dynamic_code(code))
        except (wire.CodecError, UnicodeError):
            raise SessionError('请输入有效的动态口令') from None
        with self._condition:
            if self._stop.is_set() or self._status.get('status') != 'otp' or self._otp_frame is not None:
                _wipe(frame)
                raise SessionError('当前没有待完成的动态口令')
            self._otp_frame = frame
            self._status = {'status': 'authenticating'}
            self._publish({'status': 'authenticating'})
            self._condition.notify_all()

    def disconnect(self):
        """Request teardown of this object's owned channels only.

        It sends no discovery/start/attach command. A single worker serializes
        stop/logout with all authentication operations. A prepare still running
        may finish later; cancellation is checked before any subsequent RPC.
        """
        self._stop.set()
        with self._condition:
            _wipe(self._otp_frame)
            self._otp_frame = None
            self._condition.notify_all()
            worker = self._worker
            if worker is not None and worker.ident is None:
                # _start_frame starts its worker under this same lock. A
                # registered but unstarted worker will observe stop/done.
                worker = None
        if worker is not None and worker is not threading.current_thread():
            worker.join(self.TARGET_WAIT_TIMEOUT + self.CLEANUP_TIMEOUT * 2 + 1)
            if worker.is_alive():
                raise SessionError('原生连接仍在结束，请稍后重试')
            if self._cleanup_confirmed is False:
                raise SessionError('原生连接的断开尚未确认，请检查客户端')
            if self._done.is_set():
                self._publish({'status': 'disconnected'})
        elif worker is None:
            self._done.set()
            self._publish({'status': 'disconnected'})

    def _endpoint(self):
        gateway, port = self.profile.get('gateway'), self.profile.get('port')
        if not isinstance(gateway, str) or not gateway or '\x00' in gateway:
            raise SessionError('VPN 网关地址无效')
        if type(port) is not int or not 1 <= port <= 65535:
            raise SessionError('VPN 网关端口无效')
        # Registry validation owns host/IP syntax; colons preserve IPv6 form.
        return f'[{gateway}]:{port}' if ':' in gateway else f'{gateway}:{port}'

    def _publish(self, event):
        # Only this small schema crosses into HTTP/UI state. Never add an
        # exception, native text, field array, username, or frame here.
        safe = {key: event[key] for key in ('status', 'challenge', 'error') if key in event}
        with self._condition:
            self._status = safe
        try:
            self.on_event(dict(safe))
        except Exception:
            # A UI callback failure must not produce a traceback containing
            # local worker arguments or break socket cleanup.
            pass

    def _diagnostic(self, phase, opcode, size):
        callback = getattr(self.environment, 'diagnostic', None)
        if callable(callback):
            try:
                callback(self.profile.get('id'), phase, int(opcode), int(size))
            except Exception:
                pass

    def _check_cancel(self):
        if self._stop.is_set():
            raise _Cancelled()
        if self._async_failed.is_set():
            raise SessionError('原生 VPN 通知通道已关闭')

    def _connect(self, port, *, wait_ready=False):
        if type(port) is not int or not 1 <= port <= 65535:
            raise SessionError('原生服务端口无效')
        deadline = time.monotonic() + self.CONNECT_TIMEOUT
        while True:
            self._check_cancel()
            try:
                sock = socket.create_connection(('127.0.0.1', port), timeout=min(1.0, self.CONNECT_TIMEOUT))
                sock.settimeout(0.2)
                return _Channel(sock)
            except OSError:
                if not wait_ready or time.monotonic() >= deadline:
                    raise SessionError('无法连接本机 VPN 服务') from None
                # Only an unopened TCP connection is retried while a newly
                # owned backend starts. No bootstrap/registration/auth repeats.
                self._stop.wait(0.15)

    def _send(self, channel, frame, phase, *, cleanup=False):
        if not cleanup:
            self._check_cancel()
        opcode, length = wire.HEADER.unpack_from(frame)[4:6]
        self._diagnostic(phase + '_send', opcode, length)
        try:
            channel.socket.sendall(frame)
        except OSError:
            raise SessionError('原生 VPN 通道发送失败') from None
        finally:
            # Secret-bearing mutable outgoing buffers are cleared immediately
            # after send; no queued retry may retain a password or code.
            _wipe(frame)

    def _receive(self, channel, deadline, phase, *, cleanup=False):
        while True:
            if not cleanup:
                self._check_cancel()
            if channel.pending:
                message = channel.pending.popleft()
                self._diagnostic(phase + '_receive', message.opcode, len(message.payload))
                return message
            if time.monotonic() >= deadline:
                raise SessionError('原生 VPN 响应超时')
            try:
                chunk = channel.socket.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                raise SessionError('原生 VPN 通道已关闭') from None
            if not chunk:
                raise SessionError('原生 VPN 通道已关闭')
            try:
                channel.pending.extend(channel.decoder.feed(chunk))
            except wire.CodecError:
                raise SessionError('原生 VPN 响应格式不受支持') from None

    def _exchange(self, frame, phase, timeout):
        self._phase = phase
        try:
            self._send(self._sync, frame, phase)
            return self._receive(self._sync, time.monotonic() + timeout, phase)
        finally:
            # Cancellation can occur before _send's own try/finally begins.
            _wipe(frame)

    def _require(self, message, opcode, error):
        if message.opcode != opcode:
            raise SessionError(error)

    def _bootstrap(self):
        # A caller may cancel before the asynchronous worker is scheduled.
        # prepare can close native UI/processes, so even that first boundary
        # must be guarded before entering the environment implementation.
        self._check_cancel()
        self._phase = 'prepare'
        try:
            prepared = self.environment.prepare(dict(self.profile))
        except Exception:
            raise SessionError('无法准备此 VPN 的原生实例') from None
        self._check_cancel()
        if not isinstance(prepared, dict):
            raise SessionError('原生实例准备结果无效')
        directory = prepared.get('install_directory')
        user = prepared.get('login_user_ansi')
        try:
            if isinstance(directory, str):
                # mbcs uses the actual Windows ANSI code page, unlike utf-8
                # mode. cp1252 fallback exists solely for offline tests.
                directory = directory.encode('mbcs' if hasattr(sys, 'getwindowsversion') else 'cp1252')
            registration = wire.helper_start_registration(user, directory)
        except (wire.CodecError, UnicodeError, LookupError):
            raise SessionError('原生安装路径或 Windows 用户格式无效') from None
        self._phase = 'bootstrap'
        self._helper = self._connect(prepared.get('service_port'))
        self._send(self._helper, registration, 'bootstrap')
        reply = self._receive(self._helper, time.monotonic() + self.FIRST_TIMEOUT, 'bootstrap')
        try:
            backend_port = wire.helper_port(reply)
        except wire.CodecError:
            raise SessionError('原生服务未返回有效的客户端端口') from None
        validator = getattr(self.environment, 'validate_backend', None)
        if not callable(validator):
            raise SessionError('缺少原生客户端端口归属检查')
        try:
            valid = validator(dict(self.profile), backend_port)
        except Exception:
            raise SessionError('无法确认原生客户端端口的归属') from None
        if valid is not True:
            raise SessionError('原生客户端端口不属于此 VPN 实例')
        # Retain the owned helper connection as the native GUI does; closing
        # it prematurely is not established to preserve backend lifetime.
        self._check_cancel()
        self._sync = self._connect(backend_port, wait_ready=True)
        self._send(self._sync, wire.csdk_registration(1), 'register_sync')
        self._owned = True
        self._events = self._connect(backend_port, wait_ready=True)
        self._send(self._events, wire.csdk_registration(2), 'register_events')
        self._event_worker = threading.Thread(target=self._read_events,
                                              name='UniVPN-owned-events', daemon=True)
        self._event_worker.start()

    def _read_events(self):
        channel = self._events
        try:
            while not self._stop.is_set() and not self._done.is_set():
                message = self._receive(channel, float('inf'),
                                        'event', cleanup=True)
                # Unknown async opcodes remain metadata only. Authenticating,
                # connected, challenge and error state come from proven sync
                # responses to this worker's pending request.
                del message
        except (SessionError, OSError, AttributeError):
            if not self._stop.is_set() and not self._done.is_set():
                self._async_failed.set()
                with self._condition:
                    self._condition.notify_all()

    def _wait_otp(self):
        self._phase = 'dynamic_code'
        deadline = time.monotonic() + self.OTP_TIMEOUT
        self._publish({'status': 'otp', 'challenge': '动态口令'})
        with self._condition:
            while self._otp_frame is None:
                self._check_cancel()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SessionError('动态口令等待超时，请重新连接')
                self._condition.wait(min(remaining, 0.2))
            self._check_cancel()
            frame, self._otp_frame = self._otp_frame, None
            return frame

    def _authenticate(self, login_frame):
        endpoint = self._endpoint()
        reply = self._exchange(wire.first_connect_endpoint(endpoint), 'first_connect', self.FIRST_TIMEOUT)
        self._require(reply, wire.FIRST_CONNECT_OK, '网关协商失败或需要原生客户端确认')
        try:
            metadata = wire.first_connect_metadata(reply)
        except wire.CodecError:
            raise SessionError('网关协商响应格式不受支持') from None
        # Exact auth-type/verification enums have no proven Windows mapping.
        # Do not interpret these fields as certificate acceptance or change a
        # setting based on them. The normal-password request is explicitly
        # selected by the user's submitted account/password in this adapter.
        del metadata, reply
        reply = self._exchange(wire.link_select(self.profile['gateway'], self.profile['port'], enable=0),
                               'link_select', self.FIRST_TIMEOUT)
        self._require(reply, wire.LINK_SELECT_OK, '无法选择此 VPN 网关')
        del reply
        self._check_cancel()
        self._login_sent = True
        reply = self._exchange(login_frame, 'password', self.AUTH_TIMEOUT)
        while True:
            try:
                decision = wire.auth_decision(reply)
            except wire.CodecError:
                raise SessionError('认证响应格式不受支持') from None
            del reply
            if decision['status'] == 'second_auth':
                frame = self._wait_otp()
                reply = self._exchange(frame, 'dynamic_code', self.AUTH_TIMEOUT)
                continue
            if decision['status'] == 'native_ui_required':
                if decision.get('errorCode') == 'native_password_notice':
                    raise SessionError('网关要求密码提醒或修改，请使用原生客户端完成')
                raise SessionError('网关要求原生安全检查，请使用原生客户端完成')
            if decision['status'] != 'authenticated':
                raise SessionError('认证未通过，请检查账号或动态口令')
            break
        self._publish({'status': 'authenticated'})
        self._check_cancel()
        self._publish({'status': 'starting'})
        self._tunnel_requested = True
        reply = self._exchange(wire.tunnel_start(), 'tunnel_start', self.TUNNEL_TIMEOUT)
        self._require(reply, wire.CNEM_OK, '原生 VPN 隧道建立失败')
        del reply
        try:
            ready = self.environment.wait_tunnel(dict(self.profile), timeout=self.TARGET_WAIT_TIMEOUT)
        except Exception:
            raise SessionError('无法验证此 VPN 的隧道状态') from None
        self._check_cancel()
        if ready is not True:
            raise SessionError('原生 VPN 未达到可连接状态')
        self._publish({'status': 'connected'})

    def _cleanup_request(self, frame, expected, phase):
        if not self._owned or self._sync is None:
            return False
        deadline = time.monotonic() + self.CLEANUP_TIMEOUT
        try:
            self._send(self._sync, frame, phase, cleanup=True)
            while True:
                response = self._receive(self._sync, deadline, phase, cleanup=True)
                if response.opcode == expected:
                    return True
                # A cancelled earlier operation may have left one late reply.
                # Discard it, never treating it as logout/stop confirmation.
        except (SessionError, OSError, wire.CodecError):
            return False

    def _cleanup_owned_channels(self):
        confirmed = True
        if self._tunnel_requested:
            confirmed = self._cleanup_request(wire.tunnel_stop(), wire.CNEM_STOP_OK, 'tunnel_stop') and confirmed
        if self._login_sent:
            confirmed = self._cleanup_request(wire.ssl_logout(), wire.LOGOUT_OK, 'logout') and confirmed
        self._done.set()
        for name in ('_events', '_sync', '_helper'):
            channel = getattr(self, name)
            setattr(self, name, None)
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    pass
        if self._event_worker is not None and self._event_worker is not threading.current_thread():
            try:
                self._event_worker.join(0.5)
            except RuntimeError:
                pass
        with self._condition:
            _wipe(self._otp_frame)
            self._otp_frame = None
        self._owned = False
        return confirmed

    def _cleanup(self):
        confirmed, anchor_confirmed = False, True
        try:
            confirmed = self._cleanup_owned_channels()
        except Exception:
            # Teardown must still release our never-resumed token anchor if a
            # channel or cleanup implementation fails unexpectedly.
            confirmed = False
        finally:
            release = getattr(self.environment, 'release_anchor', None)
            if callable(release):
                try:
                    release(self.profile.get('id'))
                except Exception:
                    anchor_confirmed = False
        return confirmed and anchor_confirmed

    def _run(self, login_frame):
        error = None
        try:
            self._bootstrap()
            self._authenticate(login_frame)
            while not self._stop.wait(0.2):
                self._check_cancel()
        except _Cancelled:
            pass
        except SessionError as exc:
            error = str(exc)
        except Exception:
            error = '原生 VPN 连接失败'
        finally:
            _wipe(login_frame)
            confirmed = self._cleanup()
            self._cleanup_confirmed = confirmed
            if self._stop.is_set() and not confirmed:
                self._publish({'status': 'error', 'error': '原生连接的断开尚未确认，请检查客户端'})
            else:
                self._publish({'status': 'error', 'error': error} if error and not self._stop.is_set()
                              else {'status': 'disconnected'})


# Root bridge's earlier contract used this spelling.
NativeSession = WindowsSession
