import io
import logging
import paramiko
from credential_store import decrypt

logger = logging.getLogger(__name__)


class SSHClient:
    """SSH connection manager using paramiko."""

    def __init__(self, hostname, port=22, username="root", password=None, private_key=None, timeout=30):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.timeout = timeout
        self._client = None

    @classmethod
    def from_credential(cls, hostname, credential_model, port=22):
        """Create SSHClient from a Credential database model."""
        password = None
        private_key = None

        if credential_model.auth_type == "password":
            password = decrypt(credential_model.encrypted_value)
        else:
            private_key = decrypt(credential_model.encrypted_value)

        return cls(
            hostname=hostname,
            port=port,
            username=credential_model.username,
            password=password,
            private_key=private_key,
        )

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
