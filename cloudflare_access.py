"""
Cloudflare Zero Trust (Access) integration.

When enabled, validates the Cf-Access-Jwt-Assertion header on every request.
Users are auto-provisioned from the CF Access JWT identity (email claim).

Setup:
1. Create a Cloudflare Access application for your LambNet domain
2. Configure the audience tag (Application Audience / AUD) in Settings
3. Set your CF team domain (e.g. "myteam.cloudflareaccess.com")
4. Enable CF Access auth in Settings

The JWT is validated against Cloudflare's public keys (JWKS), which are
fetched and cached from https://<team-domain>/cdn-cgi/access/certs.
"""

import json
import logging
import time
from functools import wraps
from urllib.request import urlopen, Request

import jwt as pyjwt  # PyJWT library
from flask import request, abort, g
from flask_login import login_user

from models import db, User, Setting

logger = logging.getLogger(__name__)

# Cache for Cloudflare public keys
_jwks_cache = {"keys": None, "fetched_at": 0}
JWKS_CACHE_TTL = 3600  # 1 hour


def _get_cf_config():
    """Get Cloudflare Access configuration from settings."""
    return {
        "enabled": Setting.get("cf_access_enabled", "false") == "true",
        "team_domain": Setting.get("cf_access_team_domain", ""),
        "audience": Setting.get("cf_access_audience", ""),
        "auto_provision": Setting.get("cf_access_auto_provision", "true") == "true",
        "bypass_local_auth": Setting.get("cf_access_bypass_local_auth", "false") == "true",
    }


def _fetch_jwks(team_domain):
    """Fetch Cloudflare Access public keys (JWKS) for JWT validation."""
    now = time.time()

    # Return cached keys if still valid
    if _jwks_cache["keys"] and (now - _jwks_cache["fetched_at"]) < JWKS_CACHE_TTL:
        return _jwks_cache["keys"]

    certs_url = f"https://{team_domain}/cdn-cgi/access/certs"
    try:
        req = Request(certs_url, headers={"User-Agent": "LambNet-Update-Manager"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            public_keys = data.get("public_certs", [])
            keys = []
            for key_data in data.get("keys", []):
                keys.append(pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data)))

            # Also try the public_certs format
            if not keys and public_keys:
                for cert in public_keys:
                    keys.append(cert.get("cert", ""))

            _jwks_cache["keys"] = data.get("keys", [])
            _jwks_cache["fetched_at"] = now
            return _jwks_cache["keys"]
    except Exception as e:
        logger.error(f"Failed to fetch Cloudflare JWKS from {certs_url}: {e}")
        # Return stale cache if available
        if _jwks_cache["keys"]:
            return _jwks_cache["keys"]
        return []


def validate_cf_token(token, team_domain, audience):
    """Validate a Cloudflare Access JWT token and return the decoded payload."""
    jwks = _fetch_jwks(team_domain)
    if not jwks:
        raise ValueError("Could not fetch Cloudflare public keys")

    # Try each key until one works
    jwks_client = pyjwt.PyJWKSet.from_dict({"keys": jwks})

    for jwk in jwks_client.keys:
        try:
            payload = pyjwt.decode(
                token,
                key=jwk.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=f"https://{team_domain}",
            )
            return payload
        except pyjwt.exceptions.InvalidSignatureError:
            continue
        except pyjwt.exceptions.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except pyjwt.exceptions.InvalidAudienceError:
            raise ValueError("Invalid audience")
        except Exception:
            continue

    raise ValueError("Token signature could not be verified with any key")


def _get_or_create_cf_user(email, name=None):
    """Get or auto-provision a user from CF Access identity."""
    user = User.query.filter_by(username=email).first()
    if user:
        return user

    config = _get_cf_config()
    if not config["auto_provision"]:
        return None

    # Auto-create user with basic permissions
    user = User(
        username=email,
        display_name=name or email.split("@")[0],
        role="viewer",
    )
    # Set a random unusable password (login is via CF Access)
    import secrets
    user.set_password(secrets.token_hex(32))

    db.session.add(user)
    db.session.commit()
    logger.info(f"Auto-provisioned CF Access user: {email}")
    return user


def init_cf_access(app):
    """Register Cloudflare Access middleware on the Flask app."""

    @app.before_request
    def _check_cf_access():
        """Validate CF Access JWT on every request if enabled."""
        # Skip for static files
        if request.path.startswith("/static/"):
            return

        # Skip if already authenticated (e.g. by local network bypass)
        from flask_login import current_user as _cu
        if _cu.is_authenticated:
            return

        config = _get_cf_config()
        if not config["enabled"]:
            return

        if not config["team_domain"] or not config["audience"]:
            return

        # Get the JWT from the header
        cf_token = request.headers.get("Cf-Access-Jwt-Assertion")
        if not cf_token:
            # Also check cookie (Cloudflare sets CF_Authorization cookie)
            cf_token = request.cookies.get("CF_Authorization")

        if not cf_token:
            # If CF Access is enabled and bypass is on, block unauthenticated requests
            if config["bypass_local_auth"]:
                # Allow login page for fallback
                if request.endpoint in ("auth.login", "static"):
                    return
                abort(403, description="Cloudflare Access authentication required")
            return

        try:
            payload = validate_cf_token(cf_token, config["team_domain"], config["audience"])
        except ValueError as e:
            logger.warning(f"CF Access token validation failed: {e}")
            if config["bypass_local_auth"]:
                abort(403, description=f"Invalid Cloudflare Access token: {e}")
            return

        # Token is valid - get or create user
        email = payload.get("email", "")
        name = payload.get("name", "")

        if email:
            user = _get_or_create_cf_user(email, name)
            if user and user.is_active:
                login_user(user)
                g.cf_access_user = True
            elif not user:
                logger.warning(f"CF Access: user {email} not provisioned and auto-provision is off")
                if config["bypass_local_auth"]:
                    abort(403, description="User not authorized. Contact an administrator.")

    @app.context_processor
    def _cf_access_context():
        """Make CF Access status available in templates."""
        config = _get_cf_config()
        return {
            "cf_access_enabled": config["enabled"],
            "cf_access_user": getattr(g, "cf_access_user", False),
        }
