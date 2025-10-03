from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from datetime import datetime
import uuid
from database import Database
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

BLACKBOX_FILE = 'blackbox-targets.yml'
db = Database()

def create_default_user():
    """Create a default admin user if no users exist"""
    if not db.get_all_users():
        db.create_user('admin', generate_password_hash('admin'))

def generate_yaml_file():
    """Generate the YAML file from the database content"""
    yaml_content = db.generate_yaml_content()
    with open(BLACKBOX_FILE, 'w') as file:
        file.write(yaml_content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.get_user_by_username(username)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/targets', methods=['GET'])
def get_targets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    # Get fresh from database if no temp changes exist
    has_temp_changes = len(db.temp_changes['added']) > 0 or \
                      len(db.temp_changes['deleted']) > 0 or \
                      len(db.temp_changes['toggled']) > 0

    targets = db.get_all_targets(use_temp=has_temp_changes)
    if not has_temp_changes:
        db.load_targets_to_temp()  # Refresh temp storage with database state
    return jsonify(targets)


@app.route('/check_addresses', methods=['POST'])
def check_addresses():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data or 'addresses' not in data:
        return jsonify({'error': 'No addresses provided'}), 400

    addresses = data['addresses']
    if not isinstance(addresses, list):
        return jsonify({'error': 'Addresses must be provided as a list'}), 400

    # Check for duplicate addresses in database
    duplicates = db.check_duplicate_addresses(addresses)
    return jsonify({'duplicates': duplicates})

@app.route('/target', methods=['POST'])
def add_target():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
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


@app.route('/save', methods=['POST'])
def save_changes():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    """Save all changes and generate YAML file"""
    if db.save_changes():
        generate_yaml_file()
        return jsonify({"message": "Changes saved and YAML generated successfully"})
    return jsonify({"message": "Error saving changes"}), 500


@app.route('/discard', methods=['POST'])
def discard_changes():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    """Discard all temporary changes"""
    if db.discard_changes():
        return jsonify({"message": "Changes discarded successfully"})
    return jsonify({"message": "Error discarding changes"}), 500


@app.route('/target/<int:id>', methods=['DELETE'])
def delete_target(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if db.delete_target(id):
        return jsonify({"message": "Target deleted successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/target/<int:id>/toggle', methods=['POST'])
def toggle_target(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if db.toggle_target(id):
        return jsonify({"message": "Target toggled successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/users', methods=['GET'])
def users_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    users = db.get_all_users()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['POST'])
def create_user_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password:
        hashed_password = generate_password_hash(password)
        if db.create_user(username, hashed_password):
            flash('User created successfully!')
        else:
            flash('Username already exists.')
    else:
        flash('Username and password are required.')
    return redirect(url_for('users_page'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user_route(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Prevent a user from deleting themselves
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account.")
        return redirect(url_for('users_page'))

    # Prevent deleting the last user
    if len(db.get_all_users()) <= 1:
        flash('Cannot delete the last user.')
        return redirect(url_for('users_page'))

    if db.delete_user(user_id):
        flash('User deleted successfully!')
    else:
        flash('Error deleting user.')
    return redirect(url_for('users_page'))


if __name__ == '__main__':
    with app.app_context():
        create_default_user()
    app.run(debug=True, port=8844)