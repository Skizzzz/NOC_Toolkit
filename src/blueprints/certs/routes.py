"""
Certificate management blueprint routes.

This module provides routes for certificate tracking, ISE node management,
and certificate format conversion.
"""

import csv
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List, Optional

from flask import (
    Blueprint,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)

# Create blueprint
certs_bp = Blueprint(
    "certs",
    __name__,
    template_folder="templates",
)


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def _get_cst_tz():
    """Get CST timezone object."""
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo("America/Chicago")
    except ImportError:
        import pytz
        return pytz.timezone("America/Chicago")


# ---------------------------------------------------------------------
# Certificate Tracker Routes
# ---------------------------------------------------------------------

@certs_bp.route("/certs")
def cert_tracker():
    """Main certificate tracker dashboard."""
    from src.core.security import require_login, require_page_enabled
    from tools.db_jobs import list_certificates, get_certificate_stats
    from tools.cert_tracker import get_expiry_class, get_days_until_expiry, format_expiry_date

    # Check authentication and page access
    @require_login
    @require_page_enabled("cert_tracker")
    def _inner():
        certs = list_certificates()
        stats = get_certificate_stats()

        # Get filter parameters
        cn_filter = request.args.get('cn', '').strip().lower()
        source_filter = request.args.get('source', '').strip()
        status_filter = request.args.get('status', '').strip()
        issued_to_filter = request.args.get('issued_to', '').strip().lower()
        issued_by_filter = request.args.get('issued_by', '').strip().lower()
        devices_filter = request.args.get('devices', '').strip().lower()

        # Get sort parameters
        sort_by = request.args.get('sort', '').strip()
        sort_dir = request.args.get('dir', 'asc').strip()

        # Add expiry class and days_left to each certificate for color coding
        filtered_certs = []
        for cert in certs:
            cert['expiry_class'] = get_expiry_class(cert.get('expires', ''))
            cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
            cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

            # Apply CN filter
            if cn_filter and cn_filter not in (cert.get('cn') or '').lower():
                continue

            # Apply source filter
            if source_filter and cert.get('source_type') != source_filter:
                continue

            # Apply status/expiry filter (exclusive ranges to match stats)
            if status_filter:
                days_left = cert.get('days_left')
                if status_filter == 'expired':
                    # Only expired: days < 0
                    if days_left is None or days_left >= 0:
                        continue
                elif status_filter == '14':
                    # Only 0-14 days (not expired)
                    if days_left is None or days_left < 0 or days_left > 14:
                        continue
                elif status_filter == '30':
                    # Only 15-30 days
                    if days_left is None or days_left <= 14 or days_left > 30:
                        continue
                elif status_filter == '60':
                    # Only 31-60 days
                    if days_left is None or days_left <= 30 or days_left > 60:
                        continue
                elif status_filter == 'ok':
                    # More than 60 days
                    if days_left is None or days_left <= 60:
                        continue

            # Apply issued_to filter
            if issued_to_filter and issued_to_filter not in (cert.get('issued_to') or '').lower():
                continue

            # Apply issued_by filter
            if issued_by_filter and issued_by_filter not in (cert.get('issued_by') or '').lower():
                continue

            # Apply devices filter
            devices_str = (cert.get('devices') or '') + ' ' + (cert.get('source_hostname') or '')
            if devices_filter and devices_filter not in devices_str.lower():
                continue

            filtered_certs.append(cert)

        # Apply sorting
        if sort_by == 'days':
            # Sort by days_left, putting None values at the end
            reverse = (sort_dir == 'desc')
            filtered_certs.sort(
                key=lambda c: (c.get('days_left') is None, c.get('days_left') if c.get('days_left') is not None else 9999),
                reverse=reverse
            )

        return render_template("certs/cert_tracker.html", certs=filtered_certs, stats=stats, sort_by=sort_by, sort_dir=sort_dir)

    return _inner()


@certs_bp.route("/certs/export")
def cert_export():
    """Export certificates to CSV."""
    from src.core.security import require_login
    from tools.db_jobs import list_certificates
    from tools.cert_tracker import get_days_until_expiry, format_expiry_date

    @require_login
    def _inner():
        certs = list_certificates()

        # Apply same filters as cert_tracker
        cn_filter = request.args.get('cn', '').strip().lower()
        source_filter = request.args.get('source', '').strip()
        status_filter = request.args.get('status', '').strip()
        issued_to_filter = request.args.get('issued_to', '').strip().lower()
        issued_by_filter = request.args.get('issued_by', '').strip().lower()
        devices_filter = request.args.get('devices', '').strip().lower()

        filtered_certs = []
        for cert in certs:
            cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
            cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

            if cn_filter and cn_filter not in (cert.get('cn') or '').lower():
                continue
            if source_filter and cert.get('source_type') != source_filter:
                continue
            if status_filter:
                days_left = cert.get('days_left')
                if status_filter == 'expired' and (days_left is None or days_left >= 0):
                    continue
                elif status_filter == '14' and (days_left is None or days_left < 0 or days_left > 14):
                    continue
                elif status_filter == '30' and (days_left is None or days_left <= 14 or days_left > 30):
                    continue
                elif status_filter == '60' and (days_left is None or days_left <= 30 or days_left > 60):
                    continue
                elif status_filter == 'ok' and (days_left is None or days_left <= 60):
                    continue
            if issued_to_filter and issued_to_filter not in (cert.get('issued_to') or '').lower():
                continue
            if issued_by_filter and issued_by_filter not in (cert.get('issued_by') or '').lower():
                continue
            devices_str = (cert.get('devices') or '') + ' ' + (cert.get('source_hostname') or '')
            if devices_filter and devices_filter not in devices_str.lower():
                continue

            filtered_certs.append(cert)

        # Sort by days_left ascending by default
        filtered_certs.sort(
            key=lambda c: (c.get('days_left') is None, c.get('days_left') if c.get('days_left') is not None else 9999)
        )

        # Build CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['CN', 'Expires', 'Days Left', 'Issued To', 'Issued By', 'Source', 'Devices', 'Serial'])

        for cert in filtered_certs:
            days_left = cert.get('days_left')
            if days_left is None:
                days_str = 'Unknown'
            elif days_left < 0:
                days_str = 'Expired'
            else:
                days_str = str(days_left)

            writer.writerow([
                cert.get('cn', ''),
                cert.get('expires_formatted', ''),
                days_str,
                cert.get('issued_to', ''),
                cert.get('issued_by', ''),
                cert.get('source_type', ''),
                cert.get('devices') or cert.get('source_hostname', ''),
                cert.get('serial', ''),
            ])

        output.seek(0)
        timestamp = datetime.now(_get_cst_tz()).strftime('%Y%m%d_%H%M%S')
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=certificates_{timestamp}.csv'}
        )

    return _inner()


@certs_bp.route("/certs/upload", methods=["GET", "POST"])
def cert_upload():
    """Upload a new certificate."""
    from src.core.security import require_login
    from tools.db_jobs import insert_certificate, certificate_exists
    from tools.cert_tracker import extract_full_cert_details

    @require_login
    def _inner():
        if request.method == "POST":
            if 'cert_file' not in request.files:
                flash("No file selected.", "error")
                return redirect(request.url)

            file = request.files['cert_file']
            if file.filename == '':
                flash("No file selected.", "error")
                return redirect(request.url)

            try:
                cert_bytes = file.read()
                details = extract_full_cert_details(cert_bytes)

                # Check if certificate already exists by serial number
                if details.get('serial') and certificate_exists(details['serial']):
                    flash("This certificate already exists in the tracker.", "warning")
                    return redirect(url_for('certs.cert_tracker'))

                # Insert the certificate
                cn = details.get('cn', 'Unknown')
                insert_certificate(
                    cn=cn,
                    expires=details.get('expires', 'Unknown'),
                    issued_to=details.get('issued_to', ''),
                    issued_by=details.get('issued_by', ''),
                    used_by=request.form.get('used_by', ''),
                    notes=request.form.get('notes', ''),
                    devices=request.form.get('devices', ''),
                    source_type='upload',
                    source_ip=None,
                    source_hostname=None,
                    serial=details.get('serial', ''),
                )
                flash(f"Certificate '{cn}' uploaded successfully.", "success")
                return redirect(url_for('certs.cert_tracker'))

            except Exception as e:
                flash(f"Error processing certificate: {str(e)}", "error")
                return redirect(request.url)

        return render_template("certs/cert_upload.html")

    return _inner()


@certs_bp.route("/certs/<int:cert_id>/edit", methods=["GET", "POST"])
def cert_edit(cert_id: int):
    """Edit certificate details."""
    from src.core.security import require_login
    from tools.db_jobs import get_certificate, update_certificate

    @require_login
    def _inner():
        cert = get_certificate(cert_id)
        if not cert:
            flash("Certificate not found.", "error")
            return redirect(url_for('certs.cert_tracker'))

        if request.method == "POST":
            update_certificate(
                cert_id,
                issued_to=request.form.get('issued_to', ''),
                issued_by=request.form.get('issued_by', ''),
                used_by=request.form.get('used_by', ''),
                notes=request.form.get('notes', ''),
                devices=request.form.get('devices', ''),
            )
            flash("Certificate updated successfully.", "success")
            return redirect(url_for('certs.cert_tracker'))

        return render_template("certs/cert_edit.html", cert=cert)

    return _inner()


@certs_bp.route("/certs/<int:cert_id>/delete", methods=["POST"])
def cert_delete(cert_id: int):
    """Delete a certificate."""
    from src.core.security import require_login
    from tools.db_jobs import get_certificate, delete_certificate

    @require_login
    def _inner():
        # Only superadmin can delete
        if session.get('role') != 'superadmin':
            flash("You don't have permission to delete certificates.", "error")
            return redirect(url_for('certs.cert_tracker'))

        cert = get_certificate(cert_id)
        if cert:
            delete_certificate(cert_id)
            flash(f"Certificate '{cert.get('cn', 'Unknown')}' deleted.", "success")
        else:
            flash("Certificate not found.", "error")

        return redirect(url_for('certs.cert_tracker'))

    return _inner()


@certs_bp.route("/certs/<int:cert_id>/view")
def cert_view(cert_id: int):
    """View certificate details and chain."""
    from src.core.security import require_login
    from tools.db_jobs import get_certificate
    from tools.cert_tracker import get_expiry_class, get_days_until_expiry, format_expiry_date

    @require_login
    def _inner():
        cert = get_certificate(cert_id)
        if not cert:
            flash("Certificate not found.", "error")
            return redirect(url_for('certs.cert_tracker'))

        # Add computed fields
        cert['expiry_class'] = get_expiry_class(cert.get('expires', ''))
        cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
        cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

        return render_template("certs/cert_view.html", cert=cert)

    return _inner()


@certs_bp.route("/certs/chain", methods=["POST"])
def cert_chain_view():
    """Upload and view certificate chain details."""
    from src.core.security import require_login
    from tools.cert_tracker import extract_cert_chain_details, get_days_until_expiry, format_expiry_date, get_expiry_class

    @require_login
    def _inner():
        if 'cert_file' not in request.files:
            flash("No file selected.", "error")
            return redirect(url_for('certs.cert_tracker'))

        file = request.files['cert_file']
        if file.filename == '':
            flash("No file selected.", "error")
            return redirect(url_for('certs.cert_tracker'))

        try:
            cert_bytes = file.read()
            chain = extract_cert_chain_details(cert_bytes)

            if not chain:
                flash("Could not parse certificate file.", "error")
                return redirect(url_for('certs.cert_tracker'))

            # Add computed fields to each cert in chain
            for cert in chain:
                cert['days_left'] = get_days_until_expiry(cert.get('not_after', ''))
                cert['expires_formatted'] = format_expiry_date(cert.get('not_after', ''))
                cert['expiry_class'] = get_expiry_class(cert.get('not_after', ''))

            return render_template("certs/cert_chain.html", chain=chain, filename=file.filename)

        except Exception as e:
            flash(f"Error parsing certificate: {str(e)}", "error")
            return redirect(url_for('certs.cert_tracker'))

    return _inner()


@certs_bp.route("/certs/converter", methods=["GET", "POST"])
def cert_converter():
    """Certificate format converter."""
    from src.core.security import require_login, require_page_enabled
    from tools.cert_converter import (
        CertConversionError,
        pfx_to_crt_key,
        crt_key_to_pfx,
        pem_to_crt_key,
        crt_key_to_pem,
        der_to_pem,
        pem_to_der,
        create_zip_bundle,
    )

    @require_login
    @require_page_enabled("cert_converter")
    def _inner():
        error = None
        success = None

        if request.method == "POST":
            conversion_type = request.form.get('conversion_type')
            passphrase = request.form.get('passphrase', '')

            try:
                if conversion_type == 'pfx_to_crt':
                    file1 = request.files.get('file1')
                    if not file1:
                        raise CertConversionError("No PFX file provided")

                    pfx_data = file1.read()
                    crt_data, key_data, cn = pfx_to_crt_key(pfx_data, passphrase)

                    # Create a zip bundle with both files
                    zip_data = create_zip_bundle({
                        f'{cn}.crt': crt_data,
                        f'{cn}.key': key_data,
                    })

                    response = make_response(zip_data)
                    response.headers['Content-Type'] = 'application/zip'
                    response.headers['Content-Disposition'] = f'attachment; filename={cn}_certificate.zip'
                    return response

                elif conversion_type == 'crt_key_to_pfx':
                    file1 = request.files.get('file1')
                    file2 = request.files.get('file2')
                    if not file1 or not file2:
                        raise CertConversionError("Both certificate and key files are required")
                    if not passphrase:
                        raise CertConversionError("PFX password is required")

                    crt_data = file1.read()
                    key_data = file2.read()
                    pfx_data = crt_key_to_pfx(crt_data, key_data, passphrase)

                    response = make_response(pfx_data)
                    response.headers['Content-Type'] = 'application/x-pkcs12'
                    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pfx'
                    return response

                elif conversion_type == 'pem_to_crt_key':
                    file1 = request.files.get('file1')
                    if not file1:
                        raise CertConversionError("No PEM file provided")

                    pem_data = file1.read()
                    crt_data, key_data = pem_to_crt_key(pem_data)

                    zip_data = create_zip_bundle({
                        'certificate.crt': crt_data,
                        'private.key': key_data,
                    })

                    response = make_response(zip_data)
                    response.headers['Content-Type'] = 'application/zip'
                    response.headers['Content-Disposition'] = 'attachment; filename=certificate_files.zip'
                    return response

                elif conversion_type == 'crt_key_to_pem':
                    file1 = request.files.get('file1')
                    file2 = request.files.get('file2')
                    if not file1 or not file2:
                        raise CertConversionError("Both certificate and key files are required")

                    crt_data = file1.read()
                    key_data = file2.read()
                    pem_data = crt_key_to_pem(crt_data, key_data)

                    response = make_response(pem_data)
                    response.headers['Content-Type'] = 'application/x-pem-file'
                    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
                    return response

                elif conversion_type == 'der_to_pem':
                    file1 = request.files.get('file1')
                    if not file1:
                        raise CertConversionError("No DER file provided")

                    der_data = file1.read()
                    pem_data = der_to_pem(der_data)

                    response = make_response(pem_data)
                    response.headers['Content-Type'] = 'application/x-pem-file'
                    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
                    return response

                elif conversion_type == 'pem_to_der':
                    file1 = request.files.get('file1')
                    if not file1:
                        raise CertConversionError("No PEM file provided")

                    pem_data = file1.read()
                    der_data = pem_to_der(pem_data)

                    response = make_response(der_data)
                    response.headers['Content-Type'] = 'application/x-x509-ca-cert'
                    response.headers['Content-Disposition'] = 'attachment; filename=certificate.der'
                    return response

                else:
                    raise CertConversionError("Invalid conversion type")

            except CertConversionError as e:
                error = str(e)
            except Exception as e:
                error = f"Conversion failed: {str(e)}"

        return render_template("certs/cert_converter.html", error=error, success=success)

    return _inner()


# ---------------------------------------------------------------------
# ISE Node Management Routes
# ---------------------------------------------------------------------

@certs_bp.route("/ise-nodes")
def ise_nodes():
    """ISE node management page."""
    from src.core.security import require_login, require_page_enabled
    from tools.db_jobs import list_ise_nodes, load_cert_sync_settings

    @require_login
    @require_page_enabled("ise_nodes")
    def _inner():
        nodes = list_ise_nodes()
        sync_settings = load_cert_sync_settings()
        return render_template("certs/ise_nodes.html", nodes=nodes, sync_settings=sync_settings)

    return _inner()


@certs_bp.route("/ise-nodes/add", methods=["POST"])
def ise_node_add():
    """Add a new ISE node."""
    from src.core.security import require_login
    from tools.db_jobs import insert_ise_node

    @require_login
    def _inner():
        hostname = request.form.get('hostname', '').strip()
        ip = request.form.get('ip', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not all([hostname, ip, username, password]):
            flash("All fields are required.", "error")
            return redirect(url_for('certs.ise_nodes'))

        insert_ise_node(
            hostname=hostname,
            ip=ip,
            username=username,
            password=password,
            enabled=True,
        )
        flash(f"ISE node '{hostname}' added successfully.", "success")
        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/<int:node_id>/edit", methods=["GET", "POST"])
def ise_node_edit(node_id: int):
    """Edit an ISE node."""
    from src.core.security import require_login
    from tools.db_jobs import get_ise_node, update_ise_node

    @require_login
    def _inner():
        node = get_ise_node(node_id)
        if not node:
            flash("ISE node not found.", "error")
            return redirect(url_for('certs.ise_nodes'))

        if request.method == "POST":
            # Only update password if provided
            new_password = request.form.get('password', '')
            update_ise_node(
                node_id,
                hostname=request.form.get('hostname', '').strip(),
                ip=request.form.get('ip', '').strip(),
                username=request.form.get('username', '').strip(),
                enabled=bool(request.form.get('enabled')),
                password=new_password if new_password else None,
            )
            flash("ISE node updated successfully.", "success")
            return redirect(url_for('certs.ise_nodes'))

        return render_template("certs/ise_node_edit.html", node=node)

    return _inner()


@certs_bp.route("/ise-nodes/<int:node_id>/delete", methods=["POST"])
def ise_node_delete(node_id: int):
    """Delete an ISE node."""
    from src.core.security import require_login
    from tools.db_jobs import get_ise_node, delete_ise_node

    @require_login
    def _inner():
        if session.get('role') != 'superadmin':
            flash("You don't have permission to delete ISE nodes.", "error")
            return redirect(url_for('certs.ise_nodes'))

        node = get_ise_node(node_id)
        if node:
            delete_ise_node(node_id)
            flash(f"ISE node '{node.get('hostname', 'Unknown')}' deleted.", "success")
        else:
            flash("ISE node not found.", "error")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/<int:node_id>/toggle", methods=["POST"])
def ise_node_toggle(node_id: int):
    """Toggle an ISE node enabled/disabled."""
    from src.core.security import require_login
    from tools.db_jobs import get_ise_node, update_ise_node

    @require_login
    def _inner():
        node = get_ise_node(node_id)
        if node:
            new_status = not node.get('enabled')
            update_ise_node(node_id, enabled=new_status)
            status_text = "enabled" if new_status else "disabled"
            flash(f"ISE node '{node.get('hostname', 'Unknown')}' {status_text}.", "success")
        else:
            flash("ISE node not found.", "error")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/<int:node_id>/sync", methods=["POST"])
def ise_node_sync(node_id: int):
    """Sync certificates from a single ISE node."""
    from src.core.security import require_login
    from tools.db_jobs import (
        get_ise_node,
        insert_certificate,
        certificate_exists,
        update_ise_node_sync_status,
    )
    from tools.cert_tracker import pull_ise_certs

    @require_login
    def _inner():
        node = get_ise_node(node_id)
        if not node:
            flash("ISE node not found.", "error")
            return redirect(url_for('certs.ise_nodes'))

        try:
            # Build node info for the sync function
            node_info = {
                'hostname': node['hostname'],
                'ip': node['ip'],
                'username': node['username'],
                'password': node['password'],  # get_ise_node decrypts to 'password' key
            }

            # Pull certificates from this node
            certs, sync_errors = pull_ise_certs([node_info])

            # Check if there were errors
            if sync_errors:
                error_msg = sync_errors[0]
                update_ise_node_sync_status(node_id, status='error', message=error_msg)
                flash(f"Sync failed for '{node['hostname']}': {error_msg}", "error")
                return redirect(url_for('certs.ise_nodes'))

            added_count = 0

            for cert_data in certs:
                # Check if certificate already exists
                if cert_data.get('serial') and certificate_exists(cert_data['serial']):
                    continue

                insert_certificate(
                    cn=cert_data.get('cn', 'Unknown'),
                    expires=cert_data.get('expires', 'Unknown'),
                    issued_to=cert_data.get('issued_to'),
                    issued_by=cert_data.get('issued_by'),
                    used_by=cert_data.get('used_by'),
                    notes=cert_data.get('notes'),
                    devices=cert_data.get('devices'),
                    source_type=cert_data.get('source_type', 'ise'),
                    source_ip=cert_data.get('source_ip'),
                    source_hostname=cert_data.get('source_hostname'),
                    serial=cert_data.get('serial'),
                )
                added_count += 1

            # Update node sync status
            update_ise_node_sync_status(node_id, status='success', message=f"Synced {added_count} new certificates")
            flash(f"Synced {added_count} new certificates from '{node['hostname']}'.", "success")

        except Exception as e:
            update_ise_node_sync_status(node_id, status='error', message=str(e))
            flash(f"Sync failed: {str(e)}", "error")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/sync-all", methods=["POST"])
def ise_sync_now():
    """Sync certificates from all enabled ISE nodes."""
    from src.core.security import require_login
    from tools.db_jobs import (
        get_enabled_ise_nodes,
        insert_certificate,
        certificate_exists,
        update_ise_node_sync_status,
        update_cert_sync_status,
    )
    from tools.cert_tracker import pull_ise_certs

    @require_login
    def _inner():
        nodes = get_enabled_ise_nodes()

        if not nodes:
            flash("No enabled ISE nodes configured.", "warning")
            return redirect(url_for('certs.ise_nodes'))

        total_added = 0
        node_errors = []

        # Sync each node individually to track per-node status
        for node in nodes:
            try:
                node_info = {
                    'hostname': node['hostname'],
                    'ip': node['ip'],
                    'username': node['username'],
                    'password': node['password'],
                }

                # Pull certificates from this node
                certs, sync_errors = pull_ise_certs([node_info])

                # Check if there were errors for this node
                if sync_errors:
                    node_errors.append(node['hostname'])
                    update_ise_node_sync_status(node['id'], status='error', message=sync_errors[0])
                    continue

                added_count = 0
                for cert_data in certs:
                    # Check if certificate already exists
                    if cert_data.get('serial') and certificate_exists(cert_data['serial']):
                        continue

                    insert_certificate(
                        cn=cert_data.get('cn', 'Unknown'),
                        expires=cert_data.get('expires', 'Unknown'),
                        issued_to=cert_data.get('issued_to'),
                        issued_by=cert_data.get('issued_by'),
                        used_by=cert_data.get('used_by'),
                        notes=cert_data.get('notes'),
                        devices=cert_data.get('devices'),
                        source_type=cert_data.get('source_type', 'ise'),
                        source_ip=cert_data.get('source_ip'),
                        source_hostname=cert_data.get('source_hostname'),
                        serial=cert_data.get('serial'),
                    )
                    added_count += 1

                total_added += added_count
                update_ise_node_sync_status(node['id'], status='success', message=f"Synced {added_count} new certificates")

            except Exception as e:
                node_errors.append(node['hostname'])
                update_ise_node_sync_status(node['id'], status='error', message=str(e))

        # Update global sync status
        if node_errors:
            update_cert_sync_status(status='error', message=f"Errors on: {', '.join(node_errors)}")
            flash(f"Synced {total_added} certificates. Errors on {len(node_errors)} node(s).", "warning")
        else:
            update_cert_sync_status(status='success', message=f"Synced {total_added} new certificates from {len(nodes)} nodes")
            flash(f"Synced {total_added} new certificates from {len(nodes)} ISE nodes.", "success")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/settings", methods=["POST"])
def ise_nodes_settings():
    """Update ISE auto-sync settings."""
    from src.core.security import require_login
    from tools.db_jobs import load_cert_sync_settings, save_cert_sync_settings

    @require_login
    def _inner():
        enabled = 1 if request.form.get('enabled') else 0
        interval_hours = int(request.form.get('interval_hours', 24))

        # Preserve existing sync status info
        current = load_cert_sync_settings()
        save_cert_sync_settings({
            'enabled': enabled,
            'interval_hours': interval_hours,
            'last_sync_ts': current.get('last_sync_ts'),
            'last_sync_status': current.get('last_sync_status'),
            'last_sync_message': current.get('last_sync_message'),
        })

        flash("Auto-sync settings saved.", "success")
        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/<int:node_id>/fetch-version", methods=["POST"])
def ise_node_fetch_version(node_id: int):
    """Fetch version and patch info from an ISE node."""
    from src.core.security import require_login
    from tools.db_jobs import get_ise_node, update_ise_node_version
    from tools.cert_tracker import get_ise_version

    @require_login
    def _inner():
        node = get_ise_node(node_id)
        if not node:
            flash("ISE node not found.", "error")
            return redirect(url_for('certs.ise_nodes'))

        version_info = get_ise_version(
            ip=node['ip'],
            username=node['username'],
            password=node['password'],
            hostname=node['hostname']
        )

        if version_info:
            update_ise_node_version(
                node_id,
                version=version_info.get('version', ''),
                patch=version_info.get('patch', '')
            )
            flash(f"Version info updated for {node['hostname']}.", "success")
        else:
            flash(f"Could not fetch version info from {node['hostname']}. Check console for details.", "warning")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()


@certs_bp.route("/ise-nodes/fetch-all-versions", methods=["POST"])
def ise_node_fetch_all_versions():
    """Fetch version and patch info from all enabled ISE nodes."""
    from src.core.security import require_login
    from tools.db_jobs import get_enabled_ise_nodes, update_ise_node_version
    from tools.cert_tracker import get_ise_version

    @require_login
    def _inner():
        nodes = get_enabled_ise_nodes()
        success_count = 0
        error_count = 0

        for node in nodes:
            version_info = get_ise_version(
                ip=node['ip'],
                username=node['username'],
                password=node['password'],
                hostname=node['hostname']
            )

            if version_info:
                update_ise_node_version(
                    node['id'],
                    version=version_info.get('version', ''),
                    patch=version_info.get('patch', '')
                )
                success_count += 1
            else:
                error_count += 1

        if error_count > 0:
            flash(f"Updated {success_count} node(s). Failed to fetch {error_count} node(s).", "warning")
        else:
            flash(f"Updated version info for {success_count} ISE node(s).", "success")

        return redirect(url_for('certs.ise_nodes'))

    return _inner()
