"""Tests for ssh_client.py.

All paramiko and credential_store interactions are mocked so no real SSH
connections are attempted.  Tests cover:
- Module import and class instantiation
- Default parameter values
- needs_sudo property logic
- sudo_wrap() command construction
- _feed_sudo_password() stdin interaction
- connect() — password path, private-key path, key-type fallback chain
- execute() — happy path, auto-connect, exception handling
- execute_sudo() — sudo wrapping delegation
- execute_streaming() — streaming loop, stop_fn, exception handling
- execute_sudo_streaming() — delegation
- close() — client teardown
- __enter__ / __exit__ context manager protocol
- test_connection() — success and failure paths
- from_credential() classmethod — password and key credential types
"""
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(**kwargs):
    """Return an SSHClient with sensible defaults, using only pure-Python args."""
    from clients.ssh_client import SSHClient

    defaults = dict(
        hostname="10.0.0.1",
        port=22,
        username="root",
        password=None,
        private_key=None,
        sudo_password=None,
        timeout=30,
    )
    defaults.update(kwargs)
    return SSHClient(**defaults)


def _make_credential(auth_type="password", value="s3cr3t", sudo_pw=None):
    """Return a minimal mock that looks like a Credential model instance."""
    cred = MagicMock()
    cred.auth_type = auth_type
    cred.encrypted_value = f"enc:{value}"
    cred.username = "admin"
    cred.encrypted_sudo_password = f"enc:{sudo_pw}" if sudo_pw else None
    return cred


# ---------------------------------------------------------------------------
# Import / class availability
# ---------------------------------------------------------------------------


class TestModuleImport:
    def test_ssh_client_module_imports_without_error(self):
        import clients.ssh_client  # noqa: F401

    def test_SSHClient_class_is_importable(self):
        from clients.ssh_client import SSHClient

        assert SSHClient is not None

    def test_SSHClient_is_a_class(self):
        from clients.ssh_client import SSHClient

        assert isinstance(SSHClient, type)


# ---------------------------------------------------------------------------
# Instantiation and defaults
# ---------------------------------------------------------------------------


class TestInstantiation:
    def test_instantiate_with_only_hostname(self):
        from clients.ssh_client import SSHClient

        client = SSHClient("192.168.1.1")
        assert client.hostname == "192.168.1.1"

    def test_default_port_is_22(self):
        client = _make_client()
        assert client.port == 22

    def test_default_username_is_root(self):
        client = _make_client()
        assert client.username == "root"

    def test_default_password_is_none(self):
        client = _make_client()
        assert client.password is None

    def test_default_private_key_is_none(self):
        client = _make_client()
        assert client.private_key is None

    def test_default_sudo_password_is_none(self):
        client = _make_client()
        assert client.sudo_password is None

    def test_default_timeout_is_30(self):
        client = _make_client()
        assert client.timeout == 30

    def test_internal_client_starts_as_none(self):
        client = _make_client()
        assert client._client is None

    def test_custom_port_stored(self):
        client = _make_client(port=2222)
        assert client.port == 2222

    def test_custom_timeout_stored(self):
        client = _make_client(timeout=60)
        assert client.timeout == 60

    def test_password_stored(self):
        client = _make_client(password="hunter2")
        assert client.password == "hunter2"

    def test_private_key_stored(self):
        client = _make_client(private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END")
        assert client.private_key is not None

    def test_sudo_password_stored(self):
        client = _make_client(sudo_password="sudopass")
        assert client.sudo_password == "sudopass"


# ---------------------------------------------------------------------------
# needs_sudo property
# ---------------------------------------------------------------------------


class TestNeedsSudo:
    def test_root_user_does_not_need_sudo(self):
        client = _make_client(username="root")
        assert client.needs_sudo is False

    def test_non_root_user_needs_sudo(self):
        client = _make_client(username="deploy")
        assert client.needs_sudo is True

    def test_ubuntu_user_needs_sudo(self):
        client = _make_client(username="ubuntu")
        assert client.needs_sudo is True

    def test_root_string_exact_match(self):
        """Only the literal string 'root' bypasses sudo; 'root2' must not."""
        client = _make_client(username="root2")
        assert client.needs_sudo is True


# ---------------------------------------------------------------------------
# sudo_wrap()
# ---------------------------------------------------------------------------


class TestSudoWrap:
    def test_root_user_command_unchanged(self):
        client = _make_client(username="root")
        assert client.sudo_wrap("apt-get upgrade") == "apt-get upgrade"

    def test_non_root_without_sudo_password_uses_plain_sudo(self):
        client = _make_client(username="ubuntu", sudo_password=None)
        result = client.sudo_wrap("apt-get upgrade")
        assert result == "sudo sh -c 'apt-get upgrade'"

    def test_non_root_with_sudo_password_uses_sudo_S(self):
        client = _make_client(username="ubuntu", sudo_password="pass")
        result = client.sudo_wrap("apt-get upgrade")
        assert result == "sudo -S sh -c 'apt-get upgrade'"

    def test_single_quote_in_command_is_escaped(self):
        client = _make_client(username="ubuntu", sudo_password=None)
        result = client.sudo_wrap("echo 'hello'")
        # The inner single quote must be escaped.
        assert "'\\''" in result or "\\'" in result

    def test_complex_command_wrapped_correctly(self):
        client = _make_client(username="ubuntu", sudo_password=None)
        result = client.sudo_wrap("ls -la /root")
        assert result.startswith("sudo")
        assert "ls -la /root" in result

    def test_root_with_sudo_password_still_no_wrapping(self):
        """Even if sudo_password is set, root should not be wrapped."""
        client = _make_client(username="root", sudo_password="somepass")
        assert client.sudo_wrap("id") == "id"


# ---------------------------------------------------------------------------
# _feed_sudo_password()
# ---------------------------------------------------------------------------


class TestFeedSudoPassword:
    def test_writes_password_to_stdin_for_non_root(self):
        client = _make_client(username="ubuntu", sudo_password="mypass")
        mock_stdin = MagicMock()
        client._feed_sudo_password(mock_stdin)
        mock_stdin.write.assert_called_once_with(b"mypass\n")
        mock_stdin.flush.assert_called_once()

    def test_does_nothing_for_root_even_with_sudo_password(self):
        client = _make_client(username="root", sudo_password="irrelevant")
        mock_stdin = MagicMock()
        client._feed_sudo_password(mock_stdin)
        mock_stdin.write.assert_not_called()

    def test_does_nothing_when_no_sudo_password(self):
        client = _make_client(username="ubuntu", sudo_password=None)
        mock_stdin = MagicMock()
        client._feed_sudo_password(mock_stdin)
        mock_stdin.write.assert_not_called()

    def test_password_encoded_as_utf8(self):
        client = _make_client(username="ubuntu", sudo_password="pässwörd")
        mock_stdin = MagicMock()
        client._feed_sudo_password(mock_stdin)
        written = mock_stdin.write.call_args[0][0]
        assert isinstance(written, bytes)
        assert written == "pässwörd\n".encode("utf-8")


# ---------------------------------------------------------------------------
# connect() — password auth path
# ---------------------------------------------------------------------------


class TestConnect:
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_with_password_calls_connect_correctly(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client(hostname="10.0.0.5", port=22, username="root", password="pw")
        result = client.connect()

        mock_raw.connect.assert_called_once_with(
            hostname="10.0.0.5",
            port=22,
            username="root",
            timeout=30,
            password="pw",
        )
        assert result is mock_raw

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_sets_auto_add_policy(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client(password="pw")
        client.connect()

        mock_raw.set_missing_host_key_policy.assert_called_once()

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_with_no_auth_omits_password_kwarg(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client()  # no password, no key
        client.connect()

        call_kwargs = mock_raw.connect.call_args[1]
        assert "password" not in call_kwargs
        assert "pkey" not in call_kwargs

    @patch("clients.ssh_client.paramiko.RSAKey")
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_with_rsa_private_key(self, MockSSH, MockRSA):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw
        mock_pkey = MagicMock()
        MockRSA.from_private_key.return_value = mock_pkey

        client = _make_client(private_key="-----BEGIN RSA PRIVATE KEY-----\nfake")
        client.connect()

        call_kwargs = mock_raw.connect.call_args[1]
        assert call_kwargs["pkey"] is mock_pkey
        assert "password" not in call_kwargs

    @patch("clients.ssh_client.paramiko.ECDSAKey")
    @patch("clients.ssh_client.paramiko.Ed25519Key")
    @patch("clients.ssh_client.paramiko.RSAKey")
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_falls_back_to_ed25519_when_rsa_fails(
        self, MockSSH, MockRSA, MockEd25519, MockECDSA
    ):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        import paramiko

        MockRSA.from_private_key.side_effect = paramiko.SSHException("not RSA")
        mock_ed_key = MagicMock()
        MockEd25519.from_private_key.return_value = mock_ed_key

        client = _make_client(private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nfake")
        client.connect()

        call_kwargs = mock_raw.connect.call_args[1]
        assert call_kwargs["pkey"] is mock_ed_key

    @patch("clients.ssh_client.paramiko.ECDSAKey")
    @patch("clients.ssh_client.paramiko.Ed25519Key")
    @patch("clients.ssh_client.paramiko.RSAKey")
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_falls_back_to_ecdsa_when_rsa_and_ed25519_fail(
        self, MockSSH, MockRSA, MockEd25519, MockECDSA
    ):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        import paramiko

        MockRSA.from_private_key.side_effect = paramiko.SSHException("not RSA")
        MockEd25519.from_private_key.side_effect = paramiko.SSHException("not Ed25519")
        mock_ecdsa_key = MagicMock()
        MockECDSA.from_private_key.return_value = mock_ecdsa_key

        client = _make_client(private_key="-----BEGIN EC PRIVATE KEY-----\nfake")
        client.connect()

        call_kwargs = mock_raw.connect.call_args[1]
        assert call_kwargs["pkey"] is mock_ecdsa_key

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connect_stores_internal_client(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client(password="pw")
        client.connect()

        assert client._client is mock_raw


# ---------------------------------------------------------------------------
# execute()
# ---------------------------------------------------------------------------


class TestExecute:
    def _make_exec_result(self, stdout_data="output\n", stderr_data="", exit_code=0):
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = stdout_data.encode()
        mock_stdout.channel.recv_exit_status.return_value = exit_code

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = stderr_data.encode()

        mock_stdin = MagicMock()
        return mock_stdin, mock_stdout, mock_stderr

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_returns_stdout_stderr_exit_code(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin, stdout, stderr = self._make_exec_result("hello\n", "", 0)
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        out, err, code = client.execute("echo hello")

        assert out == "hello\n"
        assert err == ""
        assert code == 0

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_auto_connects_when_client_is_none(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin, stdout, stderr = self._make_exec_result()
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        assert client._client is None

        client.execute("id")

        assert client._client is mock_raw

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_returns_minus_one_on_exception(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw
        mock_raw.exec_command.side_effect = Exception("broken pipe")

        client = _make_client(password="pw")
        client._client = mock_raw

        out, err, code = client.execute("date")

        assert out == ""
        assert "broken pipe" in err
        assert code == -1

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_with_sudo_feeds_password(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin, stdout, stderr = self._make_exec_result()
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(username="ubuntu", sudo_password="sudopass")
        client._client = mock_raw

        client.execute("sudo apt-get update", _sudo=True)

        # stdin.write must have been called with the password.
        stdin.write.assert_called_once_with(b"sudopass\n")

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_passes_timeout_to_exec_command(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin, stdout, stderr = self._make_exec_result()
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        client.execute("sleep 1", timeout=999)

        mock_raw.exec_command.assert_called_once_with("sleep 1", timeout=999)

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_execute_decodes_non_utf8_output_with_replace(self, MockSSH):
        """Binary output with invalid UTF-8 must not raise — replaced instead."""
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        # Craft invalid UTF-8 bytes.
        bad_bytes = b"valid \xff\xfe invalid"
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = bad_bytes
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()

        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        out, _, _ = client.execute("cat /bin/ls")
        assert isinstance(out, str)  # no UnicodeDecodeError


# ---------------------------------------------------------------------------
# execute_sudo()
# ---------------------------------------------------------------------------


class TestExecuteSudo:
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_root_user_command_not_wrapped(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b"root\n"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(username="root")
        client._client = mock_raw

        client.execute_sudo("id")

        cmd_used = mock_raw.exec_command.call_args[0][0]
        assert cmd_used == "id"

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_non_root_command_is_wrapped_with_sudo(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(username="ubuntu")
        client._client = mock_raw

        client.execute_sudo("apt-get update")

        cmd_used = mock_raw.exec_command.call_args[0][0]
        assert cmd_used.startswith("sudo")

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_sudo_password_fed_to_stdin_for_non_root(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(username="ubuntu", sudo_password="mypass")
        client._client = mock_raw

        client.execute_sudo("apt-get update")

        stdin.write.assert_called_once_with(b"mypass\n")


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_calls_client_close(self):
        client = _make_client()
        mock_raw = MagicMock()
        client._client = mock_raw

        client.close()

        mock_raw.close.assert_called_once()

    def test_close_resets_internal_client_to_none(self):
        client = _make_client()
        client._client = MagicMock()

        client.close()

        assert client._client is None

    def test_close_is_safe_when_already_none(self):
        client = _make_client()
        assert client._client is None
        client.close()  # must not raise


# ---------------------------------------------------------------------------
# Context manager (__enter__ / __exit__)
# ---------------------------------------------------------------------------


class TestContextManager:
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_enter_calls_connect_and_returns_self(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client(password="pw")
        result = client.__enter__()

        assert result is client
        assert client._client is mock_raw

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_exit_calls_close(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        client = _make_client(password="pw")
        client._client = mock_raw

        client.__exit__(None, None, None)

        mock_raw.close.assert_called_once()
        assert client._client is None

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_context_manager_via_with_statement(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b"ok\n"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        from clients.ssh_client import SSHClient

        with SSHClient("10.0.0.1", password="pw") as ssh:
            out, _, code = ssh.execute("echo ok")

        assert code == 0
        mock_raw.close.assert_called_once()


# ---------------------------------------------------------------------------
# test_connection()
# ---------------------------------------------------------------------------


class TestTestConnection:
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_success_when_echo_ok_returns_zero(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b"ok\n"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        ok, msg = client.test_connection()

        assert ok is True
        assert "successful" in msg.lower()

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_failure_when_exit_code_nonzero(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 1
        stderr = MagicMock()
        stderr.read.return_value = b"permission denied"
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        ok, msg = client.test_connection()

        assert ok is False

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_failure_when_connect_raises(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw
        mock_raw.connect.side_effect = Exception("Connection refused")

        client = _make_client(password="pw")
        ok, msg = client.test_connection()

        assert ok is False
        assert "Connection refused" in msg

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_failure_when_stdout_does_not_contain_ok(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b"something unexpected"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        ok, msg = client.test_connection()

        assert ok is False

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_connection_closed_after_test(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b"ok"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        mock_raw.exec_command.return_value = (stdin, stdout, stderr)

        client = _make_client(password="pw")
        client.test_connection()

        mock_raw.close.assert_called_once()


# ---------------------------------------------------------------------------
# from_credential() classmethod
# ---------------------------------------------------------------------------


class TestFromCredential:
    @patch("clients.ssh_client.decrypt")
    def test_password_credential_sets_password(self, mock_decrypt):
        mock_decrypt.return_value = "plaintext-password"
        cred = _make_credential(auth_type="password", value="enc-pw")

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred, port=22)

        assert client.password == "plaintext-password"
        assert client.private_key is None
        assert client.hostname == "10.0.0.1"

    @patch("clients.ssh_client.decrypt")
    def test_key_credential_sets_private_key(self, mock_decrypt):
        mock_decrypt.return_value = "-----BEGIN RSA PRIVATE KEY-----\nfake"
        cred = _make_credential(auth_type="key", value="enc-key")

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred)

        assert client.private_key == "-----BEGIN RSA PRIVATE KEY-----\nfake"
        assert client.password is None

    @patch("clients.ssh_client.decrypt")
    def test_sudo_password_is_decrypted_when_present(self, mock_decrypt):
        def decrypt_side_effect(val):
            return val.replace("enc:", "")

        mock_decrypt.side_effect = decrypt_side_effect
        cred = _make_credential(auth_type="password", value="enc:pw", sudo_pw="sudosecret")

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred)

        assert client.sudo_password == "sudosecret"

    @patch("clients.ssh_client.decrypt")
    def test_sudo_password_is_none_when_not_set_on_credential(self, mock_decrypt):
        mock_decrypt.return_value = "plaintext"
        cred = _make_credential(auth_type="password")
        cred.encrypted_sudo_password = None

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred)

        assert client.sudo_password is None

    @patch("clients.ssh_client.decrypt")
    def test_username_taken_from_credential(self, mock_decrypt):
        mock_decrypt.return_value = "pw"
        cred = _make_credential(auth_type="password")
        cred.username = "deploy"

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred)

        assert client.username == "deploy"

    @patch("clients.ssh_client.decrypt")
    def test_port_defaults_to_22(self, mock_decrypt):
        mock_decrypt.return_value = "pw"
        cred = _make_credential(auth_type="password")

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred)

        assert client.port == 22

    @patch("clients.ssh_client.decrypt")
    def test_custom_port_is_forwarded(self, mock_decrypt):
        mock_decrypt.return_value = "pw"
        cred = _make_credential(auth_type="password")

        from clients.ssh_client import SSHClient

        client = SSHClient.from_credential("10.0.0.1", cred, port=2222)

        assert client.port == 2222


# ---------------------------------------------------------------------------
# execute_streaming()
# ---------------------------------------------------------------------------


class TestExecuteStreaming:
    def _make_streaming_channel(self, stdout_chunks=None, stderr_chunks=None, exit_code=0):
        """Build a mock channel that simulates streaming output."""
        stdout_chunks = list(stdout_chunks or [])
        stderr_chunks = list(stderr_chunks or [])

        channel = MagicMock()
        channel.closed = False
        channel.settimeout = MagicMock()

        # recv_ready: True once per chunk, then False
        recv_ready_values = [True] * len(stdout_chunks) + [False]
        channel.recv_ready.side_effect = recv_ready_values + [False] * 100

        recv_chunks = [c.encode() if isinstance(c, str) else c for c in stdout_chunks]
        channel.recv.side_effect = recv_chunks if recv_chunks else [b""]

        # stderr_ready: True once per chunk, then False
        recv_stderr_ready_values = [True] * len(stderr_chunks) + [False]
        channel.recv_stderr_ready.side_effect = recv_stderr_ready_values + [False] * 100

        stderr_recv_chunks = [c.encode() if isinstance(c, str) else c for c in stderr_chunks]
        channel.recv_stderr.side_effect = stderr_recv_chunks if stderr_recv_chunks else [b""]

        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = exit_code

        return channel

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_streaming_calls_callback_with_output(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        channel = self._make_streaming_channel(stdout_chunks=["hello\n"])

        mock_stdout = MagicMock()
        mock_stdout.channel = channel
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()
        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        chunks = []
        client.execute_streaming("echo hello", callback=chunks.append)

        all_output = "".join(chunks)
        assert "hello" in all_output

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_streaming_returns_exit_code(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        channel = self._make_streaming_channel(exit_code=42)

        mock_stdout = MagicMock()
        mock_stdout.channel = channel
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()
        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        code = client.execute_streaming("false", callback=lambda _: None)

        assert code == 42

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_streaming_exception_calls_callback_with_error(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw
        mock_raw.exec_command.side_effect = Exception("broken pipe")

        client = _make_client(password="pw")
        client._client = mock_raw

        chunks = []
        code = client.execute_streaming("date", callback=chunks.append)

        assert code == -1
        all_output = "".join(chunks)
        assert "SSH Error" in all_output

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_streaming_stop_fn_closes_channel(self, MockSSH):
        """stop_fn returning True should cause the channel to close early."""
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        channel = MagicMock()
        channel.closed = False
        channel.settimeout = MagicMock()
        # Make it appear there is always data, but stop_fn fires immediately.
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 0

        mock_stdout = MagicMock()
        mock_stdout.channel = channel
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()
        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(password="pw")
        client._client = mock_raw

        client.execute_streaming(
            "tail -f /var/log/syslog",
            callback=lambda _: None,
            stop_fn=lambda: True,
        )

        channel.close.assert_called()


# ---------------------------------------------------------------------------
# execute_sudo_streaming()
# ---------------------------------------------------------------------------


class TestExecuteSudoStreaming:
    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_delegates_to_execute_streaming(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        channel = MagicMock()
        channel.closed = False
        channel.settimeout = MagicMock()
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 0

        mock_stdout = MagicMock()
        mock_stdout.channel = channel
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()
        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(username="root")
        client._client = mock_raw

        collected = []
        code = client.execute_sudo_streaming("apt-get upgrade -y", callback=collected.append)

        assert code == 0
        # For root, the command must not be wrapped.
        cmd_used = mock_raw.exec_command.call_args[0][0]
        assert cmd_used == "apt-get upgrade -y"

    @patch("clients.ssh_client.paramiko.SSHClient")
    def test_non_root_command_is_sudo_wrapped(self, MockSSH):
        mock_raw = MagicMock()
        MockSSH.return_value = mock_raw

        channel = MagicMock()
        channel.closed = False
        channel.settimeout = MagicMock()
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 0

        mock_stdout = MagicMock()
        mock_stdout.channel = channel
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_stdin = MagicMock()
        mock_raw.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        client = _make_client(username="ubuntu")
        client._client = mock_raw

        client.execute_sudo_streaming("apt-get upgrade -y", callback=lambda _: None)

        cmd_used = mock_raw.exec_command.call_args[0][0]
        assert cmd_used.startswith("sudo")
