from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import uuid
from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from functools import wraps

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
                flash('Please change the default password before proceeding.')
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.get_user_by_username(username)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['username'] == 'admin' and not user['password_changed']:
                session['force_password_change'] = True
                flash('Please change the default password before proceeding.')
                return redirect(url_for('force_change_password_route'))

            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'), user_role=session.get('role'))


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
        'address': request.form.get('address'),
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'short_name': request.form.get('short_name')
    }

    id = db.add_target(target_data)
    return jsonify({"message": "Target added successfully (not saved)", "id": id}), 201


@app.route('/target/<int:id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_target(id):
    target_data = {
        'address': request.form.get('address'),
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'short_name': request.form.get('short_name')
    }
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

    if db.bulk_action(action, target_ids):
        return jsonify({'message': 'Bulk action completed successfully (not saved)'})

    return jsonify({'error': 'Failed to perform bulk action'}), 500

@app.route('/users', methods=['GET'])
@login_required
@admin_required
def users_page():
    users = db.get_all_users()
    return render_template('users.html', users=users, current_user_id=session.get('user_id'))

@app.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user_route():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not all([username, password, role]):
        flash('All fields are required.')
        return redirect(url_for('users_page'))

    hashed_password = generate_password_hash(password)
    if db.create_user(username, hashed_password, role):
        flash('User created successfully!')
    else:
        flash('Username already exists.')

    return redirect(url_for('users_page'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user_route(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account.")
        return redirect(url_for('users_page'))

    if len(db.get_all_users()) <= 1:
        flash('Cannot delete the last user.')
        return redirect(url_for('users_page'))

    if db.delete_user(user_id):
        flash('User deleted successfully!')
    else:
        flash('Error deleting user.')
    return redirect(url_for('users_page'))

@app.route('/force-change-password', methods=['GET', 'POST'])
def force_change_password_route():
    if 'user_id' not in session or not session.get('force_password_change'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash('Passwords do not match or are empty.')
            return render_template('force_change_password.html', username=session.get('username'))

        hashed_password = generate_password_hash(new_password)
        if db.update_user_password(session['user_id'], hashed_password):
            session.pop('force_password_change', None)
            flash('Password updated successfully! You can now use the application.')
            return redirect(url_for('index'))
        else:
            flash('Error updating password.')

    return render_template('force_change_password.html', username=session.get('username'))

@app.route('/users/change-password/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def change_password_route(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('users_page'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both password fields are required.')
            return render_template('change_password.html', user_id=user_id, username=user['username'])

        hashed_password = generate_password_hash(new_password)
        if db.update_user_password(user_id, hashed_password):
            flash('Password updated successfully!')
            return redirect(url_for('users_page'))
        else:
            flash('Error updating password.')
            return render_template('change_password.html', user_id=user_id, username=user['username'])

    return render_template('change_password.html', user_id=user_id, username=user['username'])

@app.route('/users/change-role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_role_route(user_id):
    new_role = request.form.get('role')
    if not new_role or new_role not in ['admin', 'viewer']:
        flash('Invalid role specified.')
        return redirect(url_for('users_page'))

    if db.update_user_role(user_id, new_role):
        flash('User role updated successfully!')
    else:
        flash('Error updating user role.')

    return redirect(url_for('users_page'))


if __name__ == '__main__':
    with app.app_context():
        create_default_user()
    app.run()