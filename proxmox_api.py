import time
import logging
from proxmoxer import ProxmoxAPI
from credential_store import decrypt

logger = logging.getLogger(__name__)


class ProxmoxClient:
    """Wrapper around proxmoxer for cluster operations."""

    def __init__(self, host_model):
        self.host_model = host_model
        self._api = None

    def connect(self):
        kwargs = {
            "host": self.host_model.hostname,
            "port": self.host_model.port,
            "verify_ssl": self.host_model.verify_ssl,
        }

        if self.host_model.auth_type == "token":
            kwargs["user"] = self.host_model.username or "root@pam"
            kwargs["token_name"] = self.host_model.api_token_id
            kwargs["token_value"] = decrypt(self.host_model.api_token_secret)
        else:
            kwargs["user"] = self.host_model.username or "root@pam"
            kwargs["password"] = decrypt(self.host_model.encrypted_password)

        self._api = ProxmoxAPI(**kwargs)
        return self._api

    @property
    def api(self):
        if self._api is None:
            self.connect()
        return self._api

    def get_nodes(self):
        try:
            return self.api.nodes.get()
        except Exception as e:
            logger.error(f"Failed to get nodes from {self.host_model.hostname}: {e}")
            return []

    def get_all_guests(self):
        guests = []
        for node in self.get_nodes():
            node_name = node["node"]
            try:
                # Get VMs
                for vm in self.api.nodes(node_name).qemu.get():
                    vm["node"] = node_name
                    vm["type"] = "vm"
                    guests.append(vm)
                # Get CTs
                for ct in self.api.nodes(node_name).lxc.get():
                    ct["node"] = node_name
                    ct["type"] = "ct"
                    guests.append(ct)
            except Exception as e:
                logger.error(f"Failed to list guests on node {node_name}: {e}")
        return guests

    def get_guest_ip(self, node, vmid, guest_type):
        """Try to get guest IP from Proxmox network info."""
        try:
            if guest_type == "vm":
                ifaces = self.api.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
                for iface in ifaces.get("result", []):
                    for addr in iface.get("ip-addresses", []):
                        if addr.get("ip-address-type") == "ipv4" and not addr["ip-address"].startswith("127."):
                            return addr["ip-address"]
            else:
                config = self.api.nodes(node).lxc(vmid).config.get()
                # Parse net0 for IP
                net0 = config.get("net0", "")
                if "ip=" in net0:
                    ip_part = net0.split("ip=")[1].split(",")[0].split("/")[0]
                    return ip_part
        except Exception as e:
            logger.debug(f"Could not get IP for {guest_type}/{vmid}: {e}")
        return None

    def exec_guest_agent(self, node, vmid, command):
        """Execute a command via QEMU guest agent and return output."""
        try:
            result = self.api.nodes(node).qemu(vmid).agent.exec.post(command=command)
            pid = result.get("pid")
            if not pid:
                return None, "No PID returned"

            # Poll for completion
            for _ in range(60):
                try:
                    status = self.api.nodes(node).qemu(vmid).agent("exec-status").get(pid=pid)
                    if status.get("exited"):
                        stdout = status.get("out-data", "")
                        stderr = status.get("err-data", "")
                        exitcode = status.get("exitcode", -1)
                        if exitcode == 0:
                            return stdout, None
                        return stdout, stderr or f"Exit code {exitcode}"
                except Exception:
                    pass
                time.sleep(2)

            return None, "Timeout waiting for command"
        except Exception as e:
            return None, str(e)

    def exec_ct_command(self, node, vmid, command):
        """Execute a command inside a CT via Proxmox API (pct exec equivalent)."""
        try:
            # Use the lxc exec endpoint
            result = self.api.nodes(node).lxc(vmid).status.current.get()
            if result.get("status") != "running":
                return None, "Container is not running"

            # For CTs, we use the exec via the API - this requires SSH to the node
            # or using the Proxmox API's built-in exec (available in newer versions)
            # Fallback: we'll use SSH to the Proxmox host and run pct exec
            return None, "CT exec via API requires SSH to Proxmox host - use SSH connection method instead"
        except Exception as e:
            return None, str(e)

    def create_snapshot(self, node, vmid, guest_type, snapname, description=""):
        """Create a snapshot of a VM or CT. Returns (success, message)."""
        try:
            if guest_type == "vm":
                self.api.nodes(node).qemu(vmid).snapshot.post(
                    snapname=snapname, description=description
                )
            else:
                self.api.nodes(node).lxc(vmid).snapshot.post(
                    snapname=snapname, description=description
                )
            return True, f"Snapshot '{snapname}' created for {guest_type}/{vmid}"
        except Exception as e:
            logger.error(f"Failed to create snapshot for {guest_type}/{vmid}: {e}")
            return False, str(e)

    def find_guest_node(self, vmid):
        """Find which node a guest (VM or CT) is running on. Returns node name or None."""
        for guest in self.get_all_guests():
            if guest.get("vmid") == vmid:
                return guest.get("node")
        return None

    def test_connection(self):
        """Test API connectivity and return version info."""
        try:
            version = self.api.version.get()
            return True, f"Proxmox VE {version.get('version', 'unknown')} (release {version.get('release', '')})"
        except Exception as e:
            return False, str(e)
