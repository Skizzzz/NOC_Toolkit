"""Initial database schema with all models.

Revision ID: 001_initial
Revises:
Create Date: 2026-01-27

This migration creates all database tables for the NOC Toolkit application.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='user'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('kb_access_level', sa.String(length=50), nullable=False, server_default='FSR'),
        sa.Column('can_create_kb', sa.Boolean(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username')
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # Sessions table
    op.create_table(
        'sessions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_token')
    )
    op.create_index('ix_sessions_session_token', 'sessions', ['session_token'], unique=True)

    # App Settings table (singleton)
    op.create_table(
        'app_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('timezone', sa.String(length=100), server_default='America/Chicago'),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint('id = 1', name='singleton_app_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # Page Settings table
    op.create_table(
        'page_settings',
        sa.Column('page_key', sa.String(length=100), nullable=False),
        sa.Column('page_name', sa.String(length=255), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('page_key')
    )
    op.create_index('idx_page_settings_category', 'page_settings', ['category'])
    op.create_index('idx_page_settings_enabled', 'page_settings', ['enabled'])

    # Jobs table
    op.create_table(
        'jobs',
        sa.Column('job_id', sa.String(length=255), nullable=False),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('tool', sa.String(length=100), nullable=True),
        sa.Column('params_json', sa.Text(), nullable=True),
        sa.Column('done', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('cancelled', sa.Boolean(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('job_id')
    )
    op.create_index('idx_jobs_tool', 'jobs', ['tool'])
    op.create_index('idx_jobs_created', 'jobs', ['created'])

    # Job Events table
    op.create_table(
        'job_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('job_id', sa.String(length=255), nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=True),
        sa.Column('payload_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['job_id'], ['jobs.job_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_job_events_job', 'job_events', ['job_id'])
    op.create_index('idx_job_events_type', 'job_events', ['type'])
    op.create_index('idx_job_events_ts', 'job_events', ['ts'])

    # Audit Log table
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_log_user_id', 'audit_log', ['user_id'])
    op.create_index('idx_audit_log_username', 'audit_log', ['username'])
    op.create_index('idx_audit_log_timestamp', 'audit_log', ['timestamp'])
    op.create_index('idx_audit_log_action', 'audit_log', ['action'])

    # WLC Dashboard Settings table (singleton)
    op.create_table(
        'wlc_dashboard_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), server_default='0'),
        sa.Column('hosts_json', sa.Text(), nullable=True),
        sa.Column('username', sa.Text(), nullable=True),
        sa.Column('password', sa.Text(), nullable=True),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column('interval_sec', sa.Integer(), server_default='600'),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('last_poll_ts', sa.DateTime(), nullable=True),
        sa.Column('last_poll_status', sa.String(length=50), nullable=True),
        sa.Column('last_poll_message', sa.Text(), nullable=True),
        sa.Column('validation_json', sa.Text(), nullable=True),
        sa.Column('poll_summary_json', sa.Text(), nullable=True),
        sa.Column('aruba_hosts_json', sa.Text(), nullable=True),
        sa.Column('aruba_enabled', sa.Boolean(), server_default='0'),
        sa.CheckConstraint('id = 1', name='singleton_wlc_dashboard_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # WLC Dashboard Samples table
    op.create_table(
        'wlc_dashboard_samples',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('total_clients', sa.Integer(), nullable=True),
        sa.Column('ap_count', sa.Integer(), nullable=True),
        sa.Column('ap_details_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ts', 'host', name='idx_wlc_dash_unique')
    )
    op.create_index('idx_wlc_dash_ts', 'wlc_dashboard_samples', ['ts'])
    op.create_index('idx_wlc_dash_host', 'wlc_dashboard_samples', ['host'])

    # WLC Summer Settings table (singleton)
    op.create_table(
        'wlc_summer_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), server_default='0'),
        sa.Column('hosts_json', sa.Text(), nullable=True),
        sa.Column('username', sa.Text(), nullable=True),
        sa.Column('password', sa.Text(), nullable=True),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column('profile_names_json', sa.Text(), nullable=True),
        sa.Column('wlan_ids_json', sa.Text(), nullable=True),
        sa.Column('daily_time', sa.String(length=10), nullable=True),
        sa.Column('timezone', sa.String(length=100), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('last_poll_ts', sa.DateTime(), nullable=True),
        sa.Column('last_poll_status', sa.String(length=50), nullable=True),
        sa.Column('last_poll_message', sa.Text(), nullable=True),
        sa.Column('validation_json', sa.Text(), nullable=True),
        sa.Column('summary_json', sa.Text(), nullable=True),
        sa.CheckConstraint('id = 1', name='singleton_wlc_summer_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # WLC Summer Samples table
    op.create_table(
        'wlc_summer_samples',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('profile_name', sa.String(length=255), nullable=True),
        sa.Column('wlan_id', sa.Integer(), nullable=True),
        sa.Column('ssid', sa.String(length=255), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('status_text', sa.String(length=255), nullable=True),
        sa.Column('raw_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_wlc_summer_ts', 'wlc_summer_samples', ['ts'])
    op.create_index('idx_wlc_summer_host', 'wlc_summer_samples', ['host'])

    # AP Inventory table
    op.create_table(
        'ap_inventory',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ap_name', sa.String(length=255), nullable=True),
        sa.Column('ap_ip', sa.String(length=45), nullable=True),
        sa.Column('ap_model', sa.String(length=100), nullable=True),
        sa.Column('ap_mac', sa.String(length=17), nullable=True),
        sa.Column('ap_location', sa.Text(), nullable=True),
        sa.Column('ap_state', sa.String(length=50), nullable=True),
        sa.Column('slots', sa.Text(), nullable=True),
        sa.Column('country', sa.String(length=10), nullable=True),
        sa.Column('wlc_host', sa.String(length=255), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ap_mac', 'wlc_host', name='idx_ap_inv_mac_wlc')
    )
    op.create_index('idx_ap_inv_last_seen', 'ap_inventory', ['last_seen'])
    op.create_index('idx_ap_inv_name', 'ap_inventory', ['ap_name'])
    op.create_index('idx_ap_inv_wlc', 'ap_inventory', ['wlc_host'])
    op.create_index('idx_ap_inv_model', 'ap_inventory', ['ap_model'])

    # AP Inventory Settings table (singleton)
    op.create_table(
        'ap_inventory_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), server_default='1'),
        sa.Column('cleanup_days', sa.Integer(), server_default='5'),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint('id = 1', name='singleton_ap_inventory_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # SolarWinds Settings table (singleton)
    op.create_table(
        'solarwinds_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('base_url', sa.Text(), nullable=True),
        sa.Column('username', sa.Text(), nullable=True),
        sa.Column('password', sa.Text(), nullable=True),
        sa.Column('verify_ssl', sa.Boolean(), server_default='1'),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('last_poll_ts', sa.DateTime(), nullable=True),
        sa.Column('last_poll_status', sa.String(length=50), nullable=True),
        sa.Column('last_poll_message', sa.Text(), nullable=True),
        sa.CheckConstraint('id = 1', name='singleton_solarwinds_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # SolarWinds Nodes table
    op.create_table(
        'solarwinds_nodes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('node_id', sa.String(length=100), nullable=True),
        sa.Column('caption', sa.String(length=255), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('vendor', sa.String(length=100), nullable=True),
        sa.Column('model', sa.String(length=100), nullable=True),
        sa.Column('version', sa.String(length=100), nullable=True),
        sa.Column('hardware_version', sa.String(length=100), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('extra_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_solarwinds_node_id', 'solarwinds_nodes', ['node_id'])
    op.create_index('idx_solarwinds_caption', 'solarwinds_nodes', ['caption'])
    op.create_index('idx_solarwinds_vendor', 'solarwinds_nodes', ['vendor'])
    op.create_index('idx_solarwinds_model', 'solarwinds_nodes', ['model'])
    op.create_index('idx_solarwinds_version', 'solarwinds_nodes', ['version'])
    op.create_index('idx_solarwinds_hw_version', 'solarwinds_nodes', ['hardware_version'])

    # Bulk SSH Jobs table
    op.create_table(
        'bulk_ssh_jobs',
        sa.Column('job_id', sa.String(length=255), nullable=False),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('command', sa.Text(), nullable=True),
        sa.Column('device_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('completed_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('success_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='running'),
        sa.Column('done', sa.Boolean(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('job_id')
    )
    op.create_index('idx_bulk_ssh_jobs_created', 'bulk_ssh_jobs', ['created'])
    op.create_index('idx_bulk_ssh_jobs_username', 'bulk_ssh_jobs', ['username'])

    # Bulk SSH Results table
    op.create_table(
        'bulk_ssh_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('job_id', sa.String(length=255), nullable=False),
        sa.Column('device', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['job_id'], ['bulk_ssh_jobs.job_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_bulk_ssh_results_job', 'bulk_ssh_results', ['job_id'])
    op.create_index('idx_bulk_ssh_results_device', 'bulk_ssh_results', ['device'])

    # Bulk SSH Templates table
    op.create_table(
        'bulk_ssh_templates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('variables', sa.Text(), nullable=True),
        sa.Column('device_type', sa.String(length=100), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_bulk_ssh_templates_category', 'bulk_ssh_templates', ['category'])
    op.create_index('idx_bulk_ssh_templates_name', 'bulk_ssh_templates', ['name'])

    # Bulk SSH Schedules table
    op.create_table(
        'bulk_ssh_schedules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('hosts', sa.Text(), nullable=False),
        sa.Column('device_type', sa.String(length=100), nullable=True),
        sa.Column('schedule_type', sa.String(length=50), nullable=False),
        sa.Column('schedule_time', sa.String(length=10), nullable=True),
        sa.Column('schedule_day', sa.Integer(), nullable=True),
        sa.Column('next_run', sa.DateTime(), nullable=True),
        sa.Column('last_run', sa.DateTime(), nullable=True),
        sa.Column('last_job_id', sa.String(length=255), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_bulk_ssh_schedules_next_run', 'bulk_ssh_schedules', ['next_run'])
    op.create_index('idx_bulk_ssh_schedules_enabled', 'bulk_ssh_schedules', ['enabled'])

    # Change Windows table
    op.create_table(
        'change_windows',
        sa.Column('change_id', sa.String(length=255), nullable=False),
        sa.Column('change_number', sa.String(length=100), nullable=True),
        sa.Column('scheduled', sa.DateTime(), nullable=True),
        sa.Column('tool', sa.String(length=100), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('payload_json', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='scheduled'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.Column('result_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('change_id')
    )
    op.create_index('idx_change_windows_scheduled', 'change_windows', ['scheduled'])
    op.create_index('idx_change_windows_status', 'change_windows', ['status'])

    # Change Events table
    op.create_table(
        'change_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('change_id', sa.String(length=255), nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['change_id'], ['change_windows.change_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_change_events_change', 'change_events', ['change_id'])
    op.create_index('idx_change_events_ts', 'change_events', ['ts'])

    # Certificates table
    op.create_table(
        'certificates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cn', sa.Text(), nullable=True),
        sa.Column('expires', sa.Text(), nullable=True),
        sa.Column('issued_to', sa.Text(), nullable=True),
        sa.Column('issued_by', sa.Text(), nullable=True),
        sa.Column('used_by', sa.Text(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('devices', sa.Text(), nullable=True),
        sa.Column('source_type', sa.Text(), nullable=True),
        sa.Column('source_ip', sa.Text(), nullable=True),
        sa.Column('source_hostname', sa.Text(), nullable=True),
        sa.Column('uploaded', sa.Text(), nullable=True),
        sa.Column('updated', sa.Text(), nullable=True),
        sa.Column('serial', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_certificates_cn', 'certificates', ['cn'])
    op.create_index('idx_certificates_expires', 'certificates', ['expires'])
    op.create_index('idx_certificates_serial', 'certificates', ['serial'])

    # ISE Nodes table
    op.create_table(
        'ise_nodes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('hostname', sa.Text(), nullable=True),
        sa.Column('ip', sa.Text(), nullable=True),
        sa.Column('username', sa.Text(), nullable=True),
        sa.Column('password_encrypted', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Integer(), server_default='1'),
        sa.Column('last_sync', sa.Text(), nullable=True),
        sa.Column('last_sync_status', sa.Text(), nullable=True),
        sa.Column('last_sync_message', sa.Text(), nullable=True),
        sa.Column('created', sa.Text(), nullable=True),
        sa.Column('updated', sa.Text(), nullable=True),
        sa.Column('version', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ise_nodes_hostname', 'ise_nodes', ['hostname'])

    # Cert Sync Settings table (singleton)
    op.create_table(
        'cert_sync_settings',
        sa.Column('id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Integer(), server_default='0'),
        sa.Column('interval_hours', sa.Integer(), server_default='24'),
        sa.Column('last_sync_ts', sa.Text(), nullable=True),
        sa.Column('last_sync_status', sa.Text(), nullable=True),
        sa.Column('last_sync_message', sa.Text(), nullable=True),
        sa.CheckConstraint('id = 1', name='singleton_cert_sync_settings'),
        sa.PrimaryKeyConstraint('id')
    )

    # KB Articles table
    op.create_table(
        'kb_articles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('visibility', sa.String(length=50), nullable=False, server_default='FSR'),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_kb_articles_visibility', 'kb_articles', ['visibility'])
    op.create_index('idx_kb_articles_subject', 'kb_articles', ['subject'])


def downgrade():
    # Drop tables in reverse order to respect foreign key constraints
    op.drop_table('kb_articles')
    op.drop_table('cert_sync_settings')
    op.drop_table('ise_nodes')
    op.drop_table('certificates')
    op.drop_table('change_events')
    op.drop_table('change_windows')
    op.drop_table('bulk_ssh_schedules')
    op.drop_table('bulk_ssh_templates')
    op.drop_table('bulk_ssh_results')
    op.drop_table('bulk_ssh_jobs')
    op.drop_table('solarwinds_nodes')
    op.drop_table('solarwinds_settings')
    op.drop_table('ap_inventory_settings')
    op.drop_table('ap_inventory')
    op.drop_table('wlc_summer_samples')
    op.drop_table('wlc_summer_settings')
    op.drop_table('wlc_dashboard_samples')
    op.drop_table('wlc_dashboard_settings')
    op.drop_table('audit_log')
    op.drop_table('job_events')
    op.drop_table('jobs')
    op.drop_table('page_settings')
    op.drop_table('app_settings')
    op.drop_table('sessions')
    op.drop_table('users')
