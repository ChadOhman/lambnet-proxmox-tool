import io
import logging
import paramiko
from credential_store import decrypt

logger = logging.getLogger(__name__)


class SSHClient:
    """SSH connection manager using paramiko."""

    def __init__(self, hostname, port=22, username="root", password=None, private_key=None, sudo_password=None, timeout=30):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.sudo_password = sudo_password
        self.timeout = timeout
        self._client = None

    @classmethod
    def from_credential(cls, hostname, credential_model, port=22):
        """Create SSHClient from a Credential database model."""
        password = None
        private_key = None
        sudo_password = None

        if credential_model.auth_type == "password":
            password = decrypt(credential_model.encrypted_value)
        else:
            private_key = decrypt(credential_model.encrypted_value)

        if credential_model.encrypted_sudo_password:
            sudo_password = decrypt(credential_model.encrypted_sudo_password)

        return cls(
            hostname=hostname,
            port=port,
            username=credential_model.username,
            password=password,
            private_key=private_key,
            sudo_password=sudo_password,
        )

    @property
    def needs_sudo(self):
        """Check if commands should be wrapped with sudo (non-root user)."""
        return self.username != "root"

    def sudo_wrap(self, command):
        """Wrap a command with sudo if the user is not root.

        If a sudo password is set, pipes it via stdin using -S flag.
        Otherwise assumes passwordless sudo is configured.
        """
        if not self.needs_sudo:
            return command
        if self.sudo_password:
            # Use -S to read password from stdin, wrap command in sh -c
            escaped_cmd = command.replace("'", "'\\''")
            return f"echo '{self.sudo_password}' | sudo -S sh -c '{escaped_cmd}'"
        return f"sudo {command}"

    def connect(self):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
        }

        if self.private_key:
            key_file = io.StringIO(self.private_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except paramiko.SSHException:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except paramiko.SSHException:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            kwargs["pkey"] = pkey
        elif self.password:
            kwargs["password"] = self.password

        self._client.connect(**kwargs)
        return self._client

    def execute(self, command, timeout=120):
        """Execute a command and return (stdout, stderr, exit_code)."""
        if self._client is None:
            self.connect()

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return stdout.read().decode("utf-8", errors="replace"), stderr.read().decode("utf-8", errors="replace"), exit_code
        except Exception as e:
            logger.error(f"SSH command failed on {self.hostname}: {e}")
            return "", str(e), -1

    def execute_sudo(self, command, timeout=120):
        """Execute a command with sudo wrapping if needed."""
        return self.execute(self.sudo_wrap(command), timeout=timeout)

    def execute_streaming(self, command, callback, timeout=600):
        """Execute a command and call callback(chunk) as output arrives.

        Returns (exit_code).  The callback receives raw string chunks
        from both stdout and stderr as they become available.
        """
        import time

        if self._client is None:
            self.connect()

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            channel = stdout.channel
            channel.settimeout(0.5)

            # Stream output while the command is running
            while not channel.closed:
                got_data = False
                if channel.recv_ready():
                    data = channel.recv(4096).decode("utf-8", errors="replace")
                    if data:
                        callback(data)
                        got_data = True
                if channel.recv_stderr_ready():
                    data = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                    if data:
                        callback(data)
                        got_data = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if not got_data:
                    time.sleep(0.1)

            # Drain any remaining output using blocking reads until EOF
            remaining = stdout.read().decode("utf-8", errors="replace")
            if remaining:
                callback(remaining)
            remaining_err = stderr.read().decode("utf-8", errors="replace")
            if remaining_err:
                callback(remaining_err)

            return channel.recv_exit_status()
        except Exception as e:
            logger.error(f"SSH streaming command failed on {self.hostname}: {e}")
            callback(f"\n[SSH Error: {e}]\n")
            return -1

    def execute_sudo_streaming(self, command, callback, timeout=600):
        """Execute a command with sudo wrapping, streaming output via callback."""
        return self.execute_streaming(self.sudo_wrap(command), callback, timeout=timeout)

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def test_connection(self):
        """Test SSH connectivity."""
        try:
            self.connect()
            stdout, stderr, code = self.execute("echo ok")
            self.close()
            if code == 0 and "ok" in stdout:
                return True, "SSH connection successful"
            return False, stderr or "Unexpected output"
        except Exception as e:
            return False, str(e)
