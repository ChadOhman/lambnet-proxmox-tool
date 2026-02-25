"""
GeoIP lookup wrapper using MaxMind GeoLite2-City database.
The database file path is configured via the 'unifi_geoip_db_path' setting.
"""
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Private/reserved address ranges that should not be looked up
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_reader = None
_reader_path = None


def _is_private(ip_str):
    """Return True if the IP is private/reserved (should not be looked up)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


def _get_reader(db_path):
    """Return a (possibly cached) geoip2 Reader for the given path."""
    global _reader, _reader_path
    if _reader is not None and _reader_path == db_path:
        return _reader
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(db_path)
        _reader_path = db_path
        logger.info("GeoIP database opened: %s", db_path)
        return _reader
    except Exception as e:
        logger.warning("Could not open GeoIP database at %s: %s", db_path, e)
        _reader = None
        _reader_path = None
        return None


def lookup(ip_str, db_path):
    """
    Look up GeoIP data for an IP address.

    Returns a dict with keys: country, country_code, city.
    Returns an empty dict if the IP is private, the database is unavailable,
    or the IP is not found.
    """
    if not ip_str or not db_path:
        return {}
    if _is_private(ip_str):
        return {}
    reader = _get_reader(db_path)
    if reader is None:
        return {}
    try:
        response = reader.city(ip_str)
        return {
            "country": response.country.name or "",
            "country_code": response.country.iso_code or "",
            "city": response.city.name or "",
        }
    except Exception:
        return {}


def close():
    """Close the cached reader (call on app shutdown if needed)."""
    global _reader, _reader_path
    if _reader is not None:
        try:
            _reader.close()
        except Exception:
            pass
        _reader = None
        _reader_path = None
