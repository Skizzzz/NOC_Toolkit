# tools/cert_converter.py
"""Certificate conversion module supporting various format transformations."""
import subprocess
import tempfile
import os
import io
import zipfile
from typing import Tuple, Optional, Dict, Any


class CertConversionError(Exception):
    """Raised when certificate conversion fails."""
    pass


def pfx_to_crt_key(pfx_data: bytes, password: str = "") -> Tuple[bytes, bytes, str]:
    """
    Convert PFX/PKCS12 to CRT and KEY files.

    Args:
        pfx_data: Raw PFX file bytes
        password: PFX password

    Returns:
        Tuple of (crt_bytes, key_bytes, cn_name)
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pfx") as tmp_pfx:
        tmp_pfx.write(pfx_data)
        tmp_pfx.flush()
        pfx_path = tmp_pfx.name

    try:
        # Extract certificate
        crt_proc = subprocess.run(
            ["openssl", "pkcs12", "-in", pfx_path, "-clcerts", "-nokeys",
             "-out", "/dev/stdout", "-passin", f"pass:{password}"],
            capture_output=True
        )
        if crt_proc.returncode != 0:
            raise CertConversionError(f"Failed to extract certificate: {crt_proc.stderr.decode()}")

        # Extract private key
        key_proc = subprocess.run(
            ["openssl", "pkcs12", "-in", pfx_path, "-nocerts", "-nodes",
             "-out", "/dev/stdout", "-passin", f"pass:{password}"],
            capture_output=True
        )
        if key_proc.returncode != 0:
            raise CertConversionError(f"Failed to extract private key: {key_proc.stderr.decode()}")

        crt_data = crt_proc.stdout
        key_data = key_proc.stdout

        # Extract CN for filename
        cn = _extract_cn_from_crt(crt_data)

    finally:
        os.unlink(pfx_path)

    return crt_data, key_data, cn


def crt_key_to_pfx(crt_data: bytes, key_data: bytes, password: str) -> bytes:
    """
    Convert CRT and KEY files to PFX/PKCS12.

    Args:
        crt_data: Certificate file bytes
        key_data: Private key file bytes
        password: Password to protect the PFX

    Returns:
        PFX file bytes
    """
    if not password:
        raise CertConversionError("Password is required for PFX conversion")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as crt_file, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file_enc, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file_dec, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pfx") as pfx_file:

        crt_file.write(crt_data)
        crt_file.flush()
        key_file_enc.write(key_data)
        key_file_enc.flush()

        try:
            # Try to decrypt the private key if encrypted
            decrypt_proc = subprocess.run(
                ["openssl", "rsa", "-in", key_file_enc.name,
                 "-out", key_file_dec.name, "-passin", f"pass:{password}"],
                capture_output=True
            )

            # If decryption fails, key might not be encrypted - try using it directly
            if decrypt_proc.returncode != 0:
                key_to_use = key_file_enc.name
            else:
                key_to_use = key_file_dec.name

            # Create PFX
            pfx_proc = subprocess.run(
                ["openssl", "pkcs12", "-export",
                 "-inkey", key_to_use,
                 "-in", crt_file.name,
                 "-out", pfx_file.name,
                 "-passout", f"pass:{password}"],
                capture_output=True
            )

            if pfx_proc.returncode != 0:
                raise CertConversionError(f"PFX conversion failed: {pfx_proc.stderr.decode()}")

            with open(pfx_file.name, "rb") as f:
                pfx_data = f.read()

        finally:
            for path in [crt_file.name, key_file_enc.name, key_file_dec.name, pfx_file.name]:
                try:
                    os.unlink(path)
                except Exception:
                    pass

    return pfx_data


def pem_to_crt_key(pem_data: bytes) -> Tuple[bytes, bytes]:
    """
    Extract CRT and KEY from a combined PEM file.

    Args:
        pem_data: Combined PEM file bytes

    Returns:
        Tuple of (crt_bytes, key_bytes)
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as pem_file:
        pem_file.write(pem_data)
        pem_file.flush()
        pem_path = pem_file.name

    try:
        # Extract certificate
        crt_proc = subprocess.run(
            ["openssl", "x509", "-in", pem_path, "-outform", "PEM"],
            capture_output=True
        )

        # Extract private key
        key_proc = subprocess.run(
            ["openssl", "pkey", "-in", pem_path, "-outform", "PEM"],
            capture_output=True
        )

        crt_data = crt_proc.stdout if crt_proc.returncode == 0 else b""
        key_data = key_proc.stdout if key_proc.returncode == 0 else b""

        if not crt_data and not key_data:
            raise CertConversionError("Could not extract certificate or key from PEM file")

    finally:
        os.unlink(pem_path)

    return crt_data, key_data


def crt_key_to_pem(crt_data: bytes, key_data: bytes) -> bytes:
    """
    Combine CRT and KEY into a single PEM file.

    Args:
        crt_data: Certificate file bytes
        key_data: Private key file bytes

    Returns:
        Combined PEM file bytes
    """
    return crt_data.strip() + b"\n" + key_data.strip() + b"\n"


def der_to_pem(der_data: bytes) -> bytes:
    """
    Convert DER format certificate to PEM.

    Args:
        der_data: DER format certificate bytes

    Returns:
        PEM format certificate bytes
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as der_file:
        der_file.write(der_data)
        der_file.flush()
        der_path = der_file.name

    try:
        pem_proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", der_path, "-outform", "PEM"],
            capture_output=True
        )
        if pem_proc.returncode != 0:
            raise CertConversionError(f"DER to PEM conversion failed: {pem_proc.stderr.decode()}")
    finally:
        os.unlink(der_path)

    return pem_proc.stdout


def pem_to_der(pem_data: bytes) -> bytes:
    """
    Convert PEM format certificate to DER.

    Args:
        pem_data: PEM format certificate bytes

    Returns:
        DER format certificate bytes
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as pem_file:
        pem_file.write(pem_data)
        pem_file.flush()
        pem_path = pem_file.name

    try:
        der_proc = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-in", pem_path, "-outform", "DER"],
            capture_output=True
        )
        if der_proc.returncode != 0:
            raise CertConversionError(f"PEM to DER conversion failed: {der_proc.stderr.decode()}")
    finally:
        os.unlink(pem_path)

    return der_proc.stdout


def create_zip_bundle(files: Dict[str, bytes]) -> bytes:
    """
    Create a ZIP file containing the provided files.

    Args:
        files: Dictionary of filename -> bytes

    Returns:
        ZIP file bytes
    """
    zip_stream = io.BytesIO()
    with zipfile.ZipFile(zip_stream, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, data in files.items():
            zf.writestr(filename, data)
    zip_stream.seek(0)
    return zip_stream.read()


def _extract_cn_from_crt(crt_data: bytes) -> str:
    """Extract CN from certificate data."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp:
        tmp.write(crt_data)
        tmp.flush()
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-subject"],
            capture_output=True,
            text=True
        )
        if proc.returncode == 0:
            subject = proc.stdout.strip()
            for part in subject.split(','):
                if "CN=" in part or "CN =" in part:
                    cn = part.strip().split("CN=")[-1].split("CN =")[-1].replace("/", "_").strip()
                    return cn
    finally:
        os.unlink(tmp_path)

    return "certificate"


def get_cert_info(cert_data: bytes) -> Dict[str, Any]:
    """
    Get detailed information about a certificate.

    Args:
        cert_data: Certificate bytes (PEM or DER format)

    Returns:
        Dictionary with certificate details
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp:
        tmp.write(cert_data)
        tmp.flush()
        tmp_path = tmp.name

    try:
        # Try PEM format first
        text_proc = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-noout", "-text"],
            capture_output=True,
            text=True
        )

        # If that fails, try DER format
        if text_proc.returncode != 0:
            text_proc = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", tmp_path, "-noout", "-text"],
                capture_output=True,
                text=True
            )

        info = {
            "raw_text": text_proc.stdout if text_proc.returncode == 0 else "",
            "error": text_proc.stderr if text_proc.returncode != 0 else None
        }

        # Parse specific fields
        if text_proc.returncode == 0:
            output = text_proc.stdout

            # Extract subject
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith("Subject:"):
                    info["subject"] = line.replace("Subject:", "").strip()
                elif line.startswith("Issuer:"):
                    info["issuer"] = line.replace("Issuer:", "").strip()
                elif "Not After" in line:
                    info["not_after"] = line.split(":")[-1].strip() if ":" in line else line

    finally:
        os.unlink(tmp_path)

    return info
