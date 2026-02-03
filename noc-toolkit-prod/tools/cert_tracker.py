# tools/cert_tracker.py
"""Certificate tracking and ISE integration module."""
import logging
import subprocess
import tempfile
import os
import requests
import traceback
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from zoneinfo import ZoneInfo
import urllib3

urllib3.disable_warnings()

# Configure module logger
logger = logging.getLogger(__name__)

def _get_app_tz() -> ZoneInfo:
    """Get the configured application timezone."""
    from tools.db_jobs import get_app_timezone_info
    return get_app_timezone_info()


def get_ise_version(ip: str, username: str, password: str, hostname: str = "") -> Optional[Dict]:
    """
    Get ISE version and patch information via ISE API.

    The ISE software version is only available via ERS API on port 9060.
    ERS must be enabled on the ISE node and port 9060 must be accessible.

    Returns dict with 'version' and 'patch' keys, or None on failure.
    """
    result = {"version": "", "patch": ""}
    node_name = hostname or ip

    # ERS API is the only reliable source for ISE version
    logger.debug("[%s] Trying ERS API on port 9060...", node_name)
    try:
        url = f"https://{ip}:9060/ers/config/op/systemconfig/iseversion"
        response = requests.get(
            url,
            verify=False,
            auth=(username, password),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=10
        )

        logger.debug("[%s] ERS -> HTTP %s", node_name, response.status_code)

        if response.status_code == 200:
            data = response.json()
            version_info = data.get("OperationResult", {}).get("resultValue", [])

            for item in version_info:
                if item.get("name") == "version":
                    result["version"] = item.get("value", "")
                elif item.get("name") == "patch information":
                    result["patch"] = item.get("value", "")

            if result["version"]:
                logger.info("[%s] Success: version=%s, patch=%s", node_name, result['version'], result['patch'])
                return result
            else:
                logger.warning("[%s] ERS returned 200 but no version found", node_name)
        elif response.status_code == 401:
            logger.warning("[%s] ERS auth failed - check API credentials have ERS access", node_name)
        elif response.status_code == 403:
            logger.warning("[%s] ERS forbidden - ERS may not be enabled", node_name)
        else:
            logger.warning("[%s] ERS returned HTTP %s", node_name, response.status_code)

    except requests.exceptions.Timeout:
        logger.warning("[%s] ERS timeout - port 9060 may be blocked by firewall", node_name)
    except requests.exceptions.ConnectionError:
        logger.warning("[%s] ERS connection refused - ERS not enabled or port blocked", node_name)
    except Exception as e:
        logger.error("[%s] ERS error: %s", node_name, e)

    logger.warning("[%s] Failed - ERS API required for version info", node_name)
    return None


def extract_cn_and_expiration(cert_bytes: bytes) -> Tuple[str, str]:
    """Extract CN and expiration date from a certificate file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp_cert:
        tmp_cert.write(cert_bytes)
        tmp_cert.flush()
        tmp_path = tmp_cert.name

    try:
        cn_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-subject"],
            capture_output=True,
            text=True
        )
        exp_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-enddate"],
            capture_output=True,
            text=True
        )
    finally:
        os.unlink(tmp_path)

    cn = "Unknown"
    if cn_proc.returncode == 0:
        subject = cn_proc.stdout.strip()
        for part in subject.split(','):
            if "CN=" in part or "CN =" in part:
                cn = part.strip().split("CN=")[-1].split("CN =")[-1].replace("/", "_").strip()
                break

    expires = "Unknown"
    if exp_proc.returncode == 0:
        expires = exp_proc.stdout.replace("notAfter=", "").strip()

    return cn, expires


def extract_full_cert_details(cert_bytes: bytes) -> Dict[str, str]:
    """Extract detailed certificate information."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp_cert:
        tmp_cert.write(cert_bytes)
        tmp_cert.flush()
        tmp_path = tmp_cert.name

    try:
        # Get subject (Issued To)
        subject_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-subject"],
            capture_output=True,
            text=True
        )
        # Get issuer (Issued By)
        issuer_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-issuer"],
            capture_output=True,
            text=True
        )
        # Get expiration
        exp_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-enddate"],
            capture_output=True,
            text=True
        )
        # Get serial number
        serial_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-serial"],
            capture_output=True,
            text=True
        )
    finally:
        os.unlink(tmp_path)

    def parse_dn(dn_str: str) -> str:
        """Parse DN string to extract CN or full DN."""
        for part in dn_str.replace("subject=", "").replace("issuer=", "").split(","):
            if "CN=" in part or "CN =" in part:
                return part.strip().split("CN=")[-1].split("CN =")[-1].strip()
        return dn_str.strip()

    return {
        "cn": parse_dn(subject_proc.stdout) if subject_proc.returncode == 0 else "Unknown",
        "issued_to": parse_dn(subject_proc.stdout) if subject_proc.returncode == 0 else "Unknown",
        "issued_by": parse_dn(issuer_proc.stdout) if issuer_proc.returncode == 0 else "Unknown",
        "expires": exp_proc.stdout.replace("notAfter=", "").strip() if exp_proc.returncode == 0 else "Unknown",
        "serial": serial_proc.stdout.replace("serial=", "").strip() if serial_proc.returncode == 0 else "Unknown",
    }


def pull_ise_certs(nodes: List[Dict[str, str]], callback=None) -> Tuple[List[Dict], List[str]]:
    """
    Pull certificates from ISE nodes via REST API.

    Args:
        nodes: List of dicts with 'ip', 'hostname', 'username', 'password'
        callback: Optional callback function for logging progress

    Returns:
        Tuple of (certificates list, errors list)
    """
    certs = []
    errors = []

    def log(msg):
        if callback:
            callback(msg)
        logger.info(msg)

    log(f"Starting ISE cert pull for {len(nodes)} node(s)...")

    for node in nodes:
        ip = node.get('ip', '')
        hostname = node.get('hostname', '')
        user = node.get('username', '')
        password = node.get('password', '')

        if not ip or not user or not password:
            log(f"Skipping node {hostname or ip}: missing credentials")
            errors.append(f"{hostname or ip}: missing credentials")
            continue

        try:
            url = f"https://{ip}/api/v1/certs/system-certificate/{hostname}"
            log(f"Requesting: {url}")

            response = requests.get(
                url,
                verify=False,
                auth=(user, password),
                timeout=30
            )

            log(f"Status from {ip}: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                cert_list = data.get('response', [])
                log(f"Found {len(cert_list)} cert(s) on {hostname} ({ip})")

                for cert in cert_list:
                    cn = cert.get("friendlyName", "Unknown").strip()
                    expires = cert.get("expirationDate", "Unknown").strip()

                    # Clean up timezone info
                    for tz in ["CDT", "CST", "EDT", "EST", "PDT", "PST"]:
                        expires = expires.replace(tz, "").strip()

                    issued_to = cert.get("issuedTo", "Unknown").strip()
                    issued_by = cert.get("issuedBy", "Unknown").strip()
                    used_by = cert.get("usedBy", "Unknown").strip()
                    serial = cert.get("serialNumberDecimalFormat", "") or cert.get("serialNumber", "")

                    certs.append({
                        "cn": cn,
                        "expires": expires,
                        "issued_to": issued_to,
                        "issued_by": issued_by,
                        "used_by": used_by,
                        "source_ip": ip,
                        "source_hostname": hostname,
                        "source_type": "ise",
                        "serial": serial,
                    })
            elif response.status_code == 401:
                errors.append(f"{hostname}: Authentication failed (401)")
                log(f"Failed to pull from {ip} - Status: 401 (auth failed)")
            elif response.status_code == 404:
                errors.append(f"{hostname}: Endpoint not found (404)")
                log(f"Failed to pull from {ip} - Status: 404")
            else:
                errors.append(f"{hostname}: HTTP {response.status_code}")
                log(f"Failed to pull from {ip} - Status: {response.status_code}")

        except requests.exceptions.Timeout:
            errors.append(f"{hostname}: Connection timeout")
            log(f"Timeout when contacting {ip}")
        except requests.exceptions.ConnectionError:
            errors.append(f"{hostname}: Connection refused")
            log(f"Connection refused from {ip}")
        except Exception as e:
            errors.append(f"{hostname}: {str(e)}")
            log(f"Exception when contacting {ip}: {e}")
            logger.debug("Traceback: %s", traceback.format_exc())

    log(f"Finished ISE cert pull. Found {len(certs)} total certs, {len(errors)} errors.")
    return certs, errors


def get_days_until_expiry(expires_str: str) -> Optional[int]:
    """Calculate days until certificate expiry."""
    from dateutil import parser
    try:
        exp_date = parser.parse(expires_str).replace(tzinfo=None)
        now = datetime.now(_get_app_tz()).replace(tzinfo=None)
        delta = exp_date - now
        return delta.days
    except Exception:
        return None


def get_expiry_class(expires_str: str) -> str:
    """Return CSS class based on expiry status."""
    days = get_days_until_expiry(expires_str)
    if days is None:
        return "exp-unknown"
    if days < 0:
        return "exp-expired"
    elif days < 7:
        return "exp-critical"
    elif days < 14:
        return "exp-warning"
    elif days < 30:
        return "exp-caution"
    return "exp-ok"


def format_expiry_date(expires_str: str) -> str:
    """Format expiry date for display."""
    from dateutil import parser
    try:
        dt = parser.parse(expires_str).replace(tzinfo=None)
        return dt.strftime('%Y-%m-%d')
    except Exception:
        return expires_str


def extract_cert_chain_details(cert_bytes: bytes) -> List[Dict]:
    """
    Extract details from all certificates in a chain (PEM format).
    Returns a list of certificate details, from leaf to root.
    """
    import re

    # Split PEM into individual certificates
    pem_pattern = re.compile(
        rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        re.DOTALL
    )
    cert_pems = pem_pattern.findall(cert_bytes)

    if not cert_pems:
        # Try as single DER/binary cert
        details = extract_single_cert_details(cert_bytes)
        return [details] if details else []

    chain = []
    for i, pem in enumerate(cert_pems):
        details = extract_single_cert_details(pem)
        if details:
            details['position'] = i
            details['is_root'] = False  # Will be updated later
            chain.append(details)

    # Mark root CA (self-signed: subject == issuer)
    for cert in chain:
        if cert.get('subject_dn') == cert.get('issuer_dn'):
            cert['is_root'] = True

    return chain


def extract_single_cert_details(cert_bytes: bytes) -> Optional[Dict]:
    """Extract detailed information from a single certificate."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp_cert:
        tmp_cert.write(cert_bytes)
        tmp_cert.flush()
        tmp_path = tmp_cert.name

    try:
        # Get full text output
        text_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-text"],
            capture_output=True,
            text=True
        )

        # Get subject
        subject_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-subject"],
            capture_output=True,
            text=True
        )

        # Get issuer
        issuer_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-issuer"],
            capture_output=True,
            text=True
        )

        # Get dates
        dates_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-dates"],
            capture_output=True,
            text=True
        )

        # Get serial
        serial_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-serial"],
            capture_output=True,
            text=True
        )

        # Get fingerprint
        fingerprint_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-fingerprint", "-sha256"],
            capture_output=True,
            text=True
        )

        # Get subject alternative names
        san_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-ext", "subjectAltName"],
            capture_output=True,
            text=True
        )

    finally:
        os.unlink(tmp_path)

    if subject_proc.returncode != 0:
        return None

    def parse_dn(dn_str: str, prefix: str) -> Tuple[str, str]:
        """Parse DN string to extract CN and full DN."""
        full_dn = dn_str.replace(f"{prefix}=", "").strip()
        cn = "Unknown"
        for part in full_dn.split(","):
            if "CN=" in part or "CN =" in part:
                cn = part.strip().split("CN=")[-1].split("CN =")[-1].strip()
                break
        return cn, full_dn

    subject_cn, subject_dn = parse_dn(subject_proc.stdout.strip(), "subject")
    issuer_cn, issuer_dn = parse_dn(issuer_proc.stdout.strip(), "issuer")

    # Parse dates
    not_before = ""
    not_after = ""
    if dates_proc.returncode == 0:
        for line in dates_proc.stdout.strip().split("\n"):
            if line.startswith("notBefore="):
                not_before = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                not_after = line.replace("notAfter=", "").strip()

    # Parse SANs
    sans = []
    if san_proc.returncode == 0:
        san_text = san_proc.stdout
        import re
        dns_matches = re.findall(r'DNS:([^,\s]+)', san_text)
        ip_matches = re.findall(r'IP Address:([^,\s]+)', san_text)
        sans = dns_matches + ip_matches

    # Extract key usage and other info from text output
    key_usage = []
    ext_key_usage = []
    signature_algo = ""
    key_size = ""

    if text_proc.returncode == 0:
        text = text_proc.stdout
        import re

        # Signature algorithm
        sig_match = re.search(r'Signature Algorithm:\s*(.+)', text)
        if sig_match:
            signature_algo = sig_match.group(1).strip()

        # Key size
        key_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', text)
        if key_match:
            key_size = key_match.group(1) + " bit"

        # Key usage
        ku_match = re.search(r'X509v3 Key Usage:.*?\n\s*(.+)', text)
        if ku_match:
            key_usage = [u.strip() for u in ku_match.group(1).split(',')]

        # Extended key usage
        eku_match = re.search(r'X509v3 Extended Key Usage:.*?\n\s*(.+)', text)
        if eku_match:
            ext_key_usage = [u.strip() for u in eku_match.group(1).split(',')]

    return {
        "cn": subject_cn,
        "subject_cn": subject_cn,
        "subject_dn": subject_dn,
        "issuer_cn": issuer_cn,
        "issuer_dn": issuer_dn,
        "not_before": not_before,
        "not_after": not_after,
        "serial": serial_proc.stdout.replace("serial=", "").strip() if serial_proc.returncode == 0 else "",
        "fingerprint_sha256": fingerprint_proc.stdout.replace("sha256 Fingerprint=", "").replace("SHA256 Fingerprint=", "").strip() if fingerprint_proc.returncode == 0 else "",
        "sans": sans,
        "key_usage": key_usage,
        "ext_key_usage": ext_key_usage,
        "signature_algo": signature_algo,
        "key_size": key_size,
    }
