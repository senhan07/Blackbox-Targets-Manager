from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, Response
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import uuid
from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from functools import wraps
import re
import requests

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)

db = Database(app.config['DATABASE_FILE'])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        if session.get('force_password_change'):
            if request.endpoint not in ['force_change_password_route', 'logout', 'static']:
                return redirect(url_for('force_change_password_route'))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def create_default_user():
    """Create a default admin user if no users exist"""
    if not db.get_all_users():
        db.create_user('admin', generate_password_hash('admin'), 'admin', is_default_admin=True)

def generate_yaml_file():
    """Generate the YAML file from the database content"""
    yaml_content = db.generate_yaml_content()
    with open(app.config['BLACKBOX_FILE'], 'w') as file:
        file.write(yaml_content)

@app.before_request
def dynamic_yaml_endpoint():
    settings = db.get_settings()
    if settings and settings['yaml_endpoint_enabled']:
        if request.path == settings['yaml_endpoint_path']:
            if 'user_id' not in session:
                return redirect(url_for('login'))
            try:
                with open(app.config['BLACKBOX_FILE'], 'r') as f:
                    content = f.read()
                return Response(content, mimetype='text/plain')
            except FileNotFoundError:
                return "YAML file not found. Please save changes on the main page to generate it.", 404
    elif settings and not settings['yaml_endpoint_enabled'] and request.path == settings['yaml_endpoint_path']:
        return "Not Found", 404


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.get_user_by_username(username)

        if user and check_password_hash(user['password'], password):
            if not user['is_enabled']:
                return jsonify({'error': 'User is disabled. Please contact an administrator.'}), 403

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['username'] == 'admin' and not user['password_changed']:
                session['force_password_change'] = True
                return jsonify({'redirect': url_for('force_change_password_route')})

            return jsonify({'redirect': url_for('index')})
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    if request.args.get('from') == 'idle':
        flash('You have been logged out due to inactivity.', 'info')
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    settings = db.get_settings()
    idle_timeout = settings.get('idle_timeout_minutes', 15) if settings else 15
    return render_template('index.html', username=session.get('username'), user_role=session.get('role'), idle_timeout=idle_timeout)


@app.route('/targets', methods=['GET'])
@login_required
def get_targets():
    has_temp_changes = len(db.temp_changes['added']) > 0 or \
                      len(db.temp_changes['deleted']) > 0 or \
                      len(db.temp_changes['toggled']) > 0 or \
                      len(db.temp_changes['edited']) > 0

    targets = db.get_all_targets(use_temp=has_temp_changes)
    if not has_temp_changes:
        db.load_targets_to_temp()
    return jsonify(targets)


@app.route('/check_addresses', methods=['POST'])
@login_required
def check_addresses():
    data = request.get_json()
    if not data or 'addresses' not in data:
        return jsonify({'error': 'No addresses provided'}), 400

    addresses = data['addresses']
    if not isinstance(addresses, list):
        return jsonify({'error': 'Addresses must be provided as a list'}), 400

    duplicates = db.check_duplicate_addresses(addresses)
    return jsonify({'duplicates': duplicates})

@app.route('/target', methods=['POST'])
@login_required
@admin_required
def add_target():
    target_data = {
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'short_name': request.form.get('short_name')
    }

    # Basic validation
    if not all(target_data.values()):
        return jsonify({'error': 'All fields are required.'}), 400

    id = db.add_target(target_data)
    return jsonify({"message": "Target added successfully (not saved)", "id": id}), 201


@app.route('/target/<int:id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_target(id):
    target_data = {
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'short_name': request.form.get('short_name')
    }
    # Basic validation
    if not all(target_data.values()):
        return jsonify({'error': 'All fields are required.'}), 400

    if db.edit_target(id, target_data):
        return jsonify({"message": "Target updated successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/save', methods=['POST'])
@login_required
@admin_required
def save_changes():
    if db.save_changes():
        generate_yaml_file()
        return jsonify({"message": "Changes saved and YAML generated successfully"})
    return jsonify({"message": "Error saving changes"}), 500


@app.route('/discard', methods=['POST'])
@login_required
@admin_required
def discard_changes():
    if db.discard_changes():
        return jsonify({"message": "Changes discarded successfully"})
    return jsonify({"message": "Error discarding changes"}), 500


@app.route('/target/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_target(id):
    if db.delete_target(id):
        return jsonify({"message": "Target deleted successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/target/<int:id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_target(id):
    if db.toggle_target(id):
        return jsonify({"message": "Target toggled successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/targets/bulk_action', methods=['POST'])
@login_required
@admin_required
def bulk_action_route():
    data = request.get_json()
    action = data.get('action')
    target_ids = data.get('target_ids')

    if not all([action, target_ids]):
        return jsonify({'error': 'Missing action or target_ids'}), 400

    if action in ['delete_series', 'remove_and_delete_metrics', 'delete_target_only']:
        results = []
        for target_id in target_ids:
            if action == 'delete_series':
                result = delete_series(target_id)
            elif action == 'remove_and_delete_metrics':
                result = remove_and_delete_metrics(target_id, force=data.get('force', False))
            elif action == 'delete_target_only':
                if db.hard_delete_target(target_id):
                    result = {'success': True, 'message': 'Target deleted successfully from the database.'}
                else:
                    result = {'success': False, 'error': 'Failed to delete target from the database.'}
            results.append({'target_id': target_id, 'result': result})
        return jsonify(results)


    if db.bulk_action(action, target_ids):
        return jsonify({'message': 'Bulk action completed successfully (not saved)'})

    return jsonify({'error': 'Failed to perform bulk action'}), 500

def delete_series(target_id):
    settings = db.get_settings()
    prometheus_address = settings.get('prometheus_address')
    if not prometheus_address:
        return {'success': False, 'error': 'Prometheus address not configured in settings.'}

    target = db.get_target_by_id(target_id)
    if not target:
        return {'success': False, 'error': 'Target not found.'}

    instance = target.get('instance')
    module = target.get('module')
    short_name = target.get('short_name')
    delete_url = f'{prometheus_address}/api/v1/admin/tsdb/delete_series'
    cleanup_url = f'{prometheus_address}/api/v1/admin/tsdb/clean_tombstones'

    try:
        # Delete the series
        response = requests.post(delete_url, data={'match[]': f'{{instance="{instance}",module="{module}",short_name="{short_name}"}}'})
        if response.status_code != 204:
            return {'success': False, 'error': f'Error deleting series from Prometheus: {response.text}'}

        # Clean tombstones
        response = requests.post(cleanup_url)
        if response.status_code != 204:
            return {'success': False, 'error': f'Error cleaning tombstones in Prometheus: {response.text}'}

        return {'success': True}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Error connecting to Prometheus: {e}'}


def remove_and_delete_metrics(target_id, force=False):
    # Get target details before it's potentially deleted
    target = db.get_target_by_id(target_id)
    if not target:
        return {'success': False, 'error': 'Target not found.'}

    if not force:
        delete_result = delete_series(target_id)
        if not delete_result['success']:
            # Add target details to the error message for better context
            error_message = f"Failed to delete series for target '{target.get('short_name', 'N/A')}' ({target.get('instance', 'N/A')}): {delete_result['error']}"
            return {'success': False, 'error': error_message, 'force_option': True}

    if db.hard_delete_target(target_id):
        return {'success': True}
    else:
        return {'success': False, 'error': 'Failed to delete target from database.'}


@app.route('/target/<int:target_id>/delete_series', methods=['POST'])
@login_required
@admin_required
def delete_series_route(target_id):
    result = delete_series(target_id)
    if result['success']:
        return jsonify({'message': 'Successfully deleted series from Prometheus.'})
    else:
        return jsonify({'error': result['error']}), 500

@app.route('/target/<int:target_id>/remove_and_delete_metrics', methods=['POST'])
@login_required
@admin_required
def remove_and_delete_metrics_route(target_id):
    force = request.json.get('force', False)
    result = remove_and_delete_metrics(target_id, force)
    if result.get('success'):
        return jsonify({'message': 'Successfully removed target and deleted metrics.'})
    elif result.get('force_option'):
        return jsonify({'error': result['error'], 'force_option': True}), 500
    else:
        return jsonify({'error': result.get('error', 'An unknown error occurred.')}), 500

@app.route('/api/export/preview', methods=['POST'])
@login_required
def export_preview():
    data = request.get_json()
    filters = data.get('filters', [])

    # Basic validation for filters
    if not isinstance(filters, list):
        return jsonify({'error': 'Filters must be a list'}), 400

    valid_fields = ['instance', 'module', 'zone', 'service', 'device_type', 'connection_type', 'location', 'short_name', 'enabled']

    for f in filters:
        if not all(k in f for k in ['field', 'operator', 'value']):
            return jsonify({'error': 'Invalid filter format'}), 400
        if f['field'] not in valid_fields:
            return jsonify({'error': f"Invalid filter field: {f['field']}"}), 400

    filtered_targets = db.get_filtered_targets(filters)
    return jsonify(filtered_targets)

@app.route('/health')
def health_check():
    return jsonify(status='ok')

@app.route('/users', methods=['GET'])
@login_required
@admin_required
def users_page():
    users = db.get_all_users()
    return render_template('users.html', users=users, current_user_id=session.get('user_id'))

@app.route('/settings', methods=['GET'])
@login_required
@admin_required
def settings_page():
    return render_template('settings.html')

@app.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user_route():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not all([username, password, role]):
        return jsonify({'error': 'All fields are required.'}), 400

    hashed_password = generate_password_hash(password)
    if db.create_user(username, hashed_password, role):
        return jsonify({'message': 'User created successfully!'})
    else:
        return jsonify({'error': 'Username already exists.'}), 409

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user_route(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': 'You cannot delete your own account.'}), 403

    users = db.get_all_users()
    if len(users) <= 1:
        return jsonify({'error': 'Cannot delete the last user.'}), 403

    target_user = next((user for user in users if user['id'] == user_id), None)

    if target_user and target_user['role'] == 'admin':
        admin_users = [user for user in users if user['role'] == 'admin']
        if len(admin_users) <= 1:
            return jsonify({'error': 'Cannot delete the last admin user.'}), 403

    if db.delete_user(user_id):
        return jsonify({'message': 'User deleted successfully!'})
    else:
        return jsonify({'error': 'Error deleting user.'}), 500

@app.route('/force-change-password', methods=['GET', 'POST'])
def force_change_password_route():
    if 'user_id' not in session or not session.get('force_password_change'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match or are empty.'}), 400

        hashed_password = generate_password_hash(new_password)
        if db.update_user_password(session['user_id'], hashed_password):
            session.pop('force_password_change', None)
            return jsonify({'message': 'Password updated successfully! You can now use the application.', 'redirect': url_for('index')})
        else:
            return jsonify({'error': 'Error updating password.'}), 500

    return render_template('force_change_password.html', username=session.get('username'))

@app.route('/users/change-password/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def change_password_route(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password or new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match or are empty.'}), 400

        hashed_password = generate_password_hash(new_password)
        if db.update_user_password(user_id, hashed_password):
            return jsonify({'message': 'Password updated successfully!'})
        else:
            return jsonify({'error': 'Error updating password.'}), 500

    return render_template('change_password.html', user_id=user_id, username=user['username'])

@app.route('/users/change-role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_role_route(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': 'You cannot change your own role.'}), 403

    new_role = request.form.get('role')
    if not new_role or new_role not in ['admin', 'viewer']:
        return jsonify({'error': 'Invalid role specified.'}), 400

    if db.update_user_role(user_id, new_role):
        return jsonify({'message': 'User role updated successfully!'})
    else:
        return jsonify({'error': 'Error updating user role.'}), 500

@app.route('/users/toggle-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_status_route(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': "You cannot disable your own account."}), 403

    users = db.get_all_users()
    target_user = next((user for user in users if user['id'] == user_id), None)

    if target_user and target_user['role'] == 'admin':
        admin_users = [user for user in users if user['role'] == 'admin' and user['is_enabled']]
        if len(admin_users) <= 1 and target_user['is_enabled']:
            return jsonify({'error': 'Cannot disable the last enabled admin user.'}), 403

    if db.toggle_user_status(user_id):
        return jsonify({'message': 'User status updated successfully!'})
    else:
        return jsonify({'error': 'Error updating user status.'}), 500


@app.route('/api/settings', methods=['GET'])
@login_required
@admin_required
def get_settings():
    settings = db.get_settings()
    return jsonify(settings)

@app.route('/api/settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Validate yaml_endpoint_path
    path = data.get('yaml_endpoint_path')
    if not path or not re.match(r'^/[a-zA-Z0-9-]+$', path):
        return jsonify({'error': 'Invalid YAML endpoint path. It must start with / and contain only letters, numbers, and hyphens.'}), 400

    # Validate idle_timeout_minutes
    timeout = data.get('idle_timeout_minutes')
    if not isinstance(timeout, int) or timeout < 1:
        return jsonify({'error': 'Idle timeout must be a positive integer.'}), 400

    # Validate yaml_endpoint_enabled
    enabled = data.get('yaml_endpoint_enabled')
    if not isinstance(enabled, bool):
        return jsonify({'error': 'YAML endpoint enabled must be a boolean.'}), 400

    prometheus_address = data.get('prometheus_address')
    if not prometheus_address or not (prometheus_address.startswith('http://') or prometheus_address.startswith('https://')):
        return jsonify({'error': 'Invalid Prometheus address. It must start with http:// or https://'}), 400

    blackbox_prober_address = data.get('blackbox_prober_address')
    if not blackbox_prober_address or '://' in blackbox_prober_address:
        return jsonify({'error': 'Invalid Blackbox prober address. It should be in the format host:port.'}), 400


    settings_data = {
        'yaml_endpoint_enabled': enabled,
        'yaml_endpoint_path': path,
        'idle_timeout_minutes': timeout,
        'prometheus_address': prometheus_address,
        'blackbox_prober_address': blackbox_prober_address
    }

    if db.update_settings(settings_data):
        return jsonify({'message': 'Settings updated successfully!'})
    else:
        return jsonify({'error': 'Failed to update settings'}), 500

@app.route('/check_connection', methods=['POST'])
@login_required
@admin_required
def check_connection():
    data = request.get_json()
    service = data.get('service')
    address = data.get('address')

    if not service or not address:
        return jsonify({'error': 'Service and address are required'}), 400

    if service not in ['prometheus', 'blackbox']:
        return jsonify({'error': 'Invalid service specified'}), 400

    url = address if '://' in address else f'http://{address}'

    try:
        if service == 'prometheus':
            # Prometheus readiness check
            response = requests.get(f'{url}/-/ready', timeout=5)
        else: # blackbox
            # Blackbox health check
            response = requests.get(f'{url}/health', timeout=5)

        response.raise_for_status()
        return jsonify({'success': True, 'message': 'Connection successful'})

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        create_default_user()
    app.run(host='0.0.0.0', port=8844)