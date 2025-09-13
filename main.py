from flask import Flask, request, jsonify, render_template
from datetime import datetime
import uuid
from database import Database
import os

app = Flask(__name__)

BLACKBOX_FILE = 'blackbox-targets.yml'
db = Database()

def generate_yaml_file():
    """Generate the YAML file from the database content"""
    yaml_content = db.generate_yaml_content()
    with open(BLACKBOX_FILE, 'w') as file:
        file.write(yaml_content)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/targets', methods=['GET'])
def get_targets():
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
    target_data = {
        'address': request.form.get('address'),
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'geohash': request.form.get('geohash'),
        'short_name': request.form.get('short_name'),
        'target_name': request.form.get('target_name')
    }

    id = db.add_target(target_data)
    return jsonify({"message": "Target added successfully (not saved)", "id": id}), 201


@app.route('/save', methods=['POST'])
def save_changes():
    """Save all changes and generate YAML file"""
    if db.save_changes():
        generate_yaml_file()
        return jsonify({"message": "Changes saved and YAML generated successfully"})
    return jsonify({"message": "Error saving changes"}), 500


@app.route('/discard', methods=['POST'])
def discard_changes():
    """Discard all temporary changes"""
    if db.discard_changes():
        return jsonify({"message": "Changes discarded successfully"})
    return jsonify({"message": "Error discarding changes"}), 500


@app.route('/target/<int:id>', methods=['DELETE'])
def delete_target(id):
    if db.delete_target(id):
        return jsonify({"message": "Target deleted successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


@app.route('/target/<int:id>/toggle', methods=['POST'])
def toggle_target(id):
    if db.toggle_target(id):
        return jsonify({"message": "Target toggled successfully (not saved)"})
    return jsonify({"message": "Target not found"}), 404


if __name__ == '__main__':
    app.run(debug=True)