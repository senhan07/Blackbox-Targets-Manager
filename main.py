from flask import Flask, request, jsonify, render_template
import yaml
from datetime import datetime
import re
import uuid

app = Flask(__name__)

BLACKBOX_FILE = 'blackbox-target.yml'

def parse_target(target_string):
    match = re.search(r'#ADDED (\d{4}-\d{2}-\d{2})$', target_string)
    date_added = match.group(1) if match else "Unknown"

    uid_match = re.search(r'#UID ([\w-]+)', target_string)
    uid = uid_match.group(1) if uid_match else "Unknown"

    fields = target_string.split(';')
    if len(fields) != 11:
        print(f"Skipping invalid target line: {target_string}")
        return None

    return {
        '__address__': fields[0],
        'instance': fields[1],
        'module': fields[2],
        'zone': fields[3],
        'service': fields[4],
        'device_type': fields[5],
        'connection_type': fields[6],
        'location': fields[7],
        'geohash': fields[8],
        'target_name': fields[9],
        'description': fields[10].split('#')[0].strip(),  # Remove any trailing comments
        'date_added': date_added,
        'uid': uid
    }


def load_targets():
    with open(BLACKBOX_FILE, 'r') as file:
        lines = file.readlines()

    targets = []
    inside_targets_section = False

    for line in lines:
        stripped_line = line.strip()

        if stripped_line == "- targets:":
            inside_targets_section = True
            continue

        if inside_targets_section and stripped_line:
            is_commented = line.lstrip().startswith("#")
            target_data = stripped_line.lstrip("# ").strip()
            target = parse_target(target_data)
            if target:
                target['enabled'] = not is_commented
                targets.append(target)
    return targets


def save_targets(targets):
    with open(BLACKBOX_FILE, 'w') as file:
        yaml.dump([{'targets': targets}], file, default_flow_style=False)


def toggle_target_in_file(uid):
    with open(BLACKBOX_FILE, 'r') as file:
        lines = file.readlines()

    updated_lines = []
    inside_targets_section = False

    for line in lines:
        stripped_line = line.strip()

        # Detect the start of the `- targets:` section
        if stripped_line == "- targets:":
            inside_targets_section = True
            updated_lines.append(line)
            continue

        if inside_targets_section:
            # Handle both commented and uncommented lines
            if stripped_line.startswith("# -"):
                target_data = stripped_line.lstrip("# - ").strip()
                is_commented = True
            else:
                target_data = stripped_line.lstrip("- ").strip()
                is_commented = False

            # Extract the target info and the `#ADDED` part
            parts = target_data.split(" #ADDED ")
            target_info = parts[0]
            added_timestamp = f" #ADDED {parts[1]}" if len(parts) > 1 else ""

            # Extract the UID from the target info
            uid_match = re.search(r'#UID (\S+)', target_info)
            target_uid = uid_match.group(1) if uid_match else None

            # Debugging print
            print(f"Target: {target_info}, UID: {target_uid}, Commented: {is_commented}")

            # If the UID matches, toggle the comment
            if target_uid == uid:
                if is_commented:
                    updated_lines.append(f"  - {target_info}{added_timestamp}\n")
                else:
                    updated_lines.append(f"  # - {target_info}{added_timestamp}\n")
                continue

        updated_lines.append(line)

    # Write the updated lines back to the file
    with open(BLACKBOX_FILE, 'w') as file:
        file.writelines(updated_lines)


@app.route('/')
def index():
    targets = load_targets()
    return render_template('index.html', targets=targets)


@app.route('/targets', methods=['GET'])
def get_targets():
    targets = load_targets()
    response_data = []

    for target in targets:
        uid_match = re.search(r'#UID (\S+)', target.get('description', ''))
        uid = uid_match.group(1) if uid_match else None

        response_data.append({
            'uid': uid,  # Use UID in response
            '__address__': target['__address__'],
            'module': target['module'],
            'zone': target['zone'],
            'service': target['service'],
            'device_type': target['device_type'],
            'connection_type': target['connection_type'],
            'location': target['location'],
            'geohash': target['geohash'],
            'target_name': target['target_name'],
            'description': target['description'].split('#')[0].strip(),
            'date_added': target['date_added'],
            'enabled': target['enabled']
        })

    return jsonify(response_data)



@app.route('/target', methods=['POST'])
def add_target():
    # uid = secrets.token_hex(3)  # Generate a unique UID
    uid = str(uuid.uuid4())[:8]  # Generate a unique UID

    new_target = {
        '__address__': request.form.get('address'),
        'instance': request.form.get('instance'),
        'module': request.form.get('module'),
        'zone': request.form.get('zone'),
        'service': request.form.get('service'),
        'device_type': request.form.get('device_type'),
        'connection_type': request.form.get('connection_type'),
        'location': request.form.get('location'),
        'geohash': request.form.get('geohash'),
        'target_name': request.form.get('target_name'),
        'description': request.form.get('description')
    }

    timestamp = datetime.now().strftime('%Y-%m-%d')

    # Format the new target string (storing instance but adding UID as a comment)
    new_target_string = f"\n  - {new_target['__address__']};{new_target['instance']};{new_target['module']};" \
                        f"{new_target['zone']};{new_target['service']};{new_target['device_type']};" \
                        f"{new_target['connection_type']};{new_target['location']};{new_target['geohash']};" \
                        f"{new_target['target_name']};{new_target['description']} #UID {uid} #ADDED {timestamp}"

    with open(BLACKBOX_FILE, 'r') as file:
        lines = file.readlines()

    updated_lines = []
    inside_targets_section = False
    target_added = False

    for line in lines:
        stripped_line = line.strip()
        updated_lines.append(line)

        if stripped_line == "- targets:":
            inside_targets_section = True

        if inside_targets_section and (line.strip() == "" or line == lines[-1]):
            if not target_added:
                updated_lines.append(new_target_string)
                target_added = True

    if not inside_targets_section:
        updated_lines.append("\n- targets:\n")
        updated_lines.append(new_target_string)

    with open(BLACKBOX_FILE, 'w') as file:
        file.writelines(updated_lines)

    return jsonify({"message": "Target added successfully", "uid": uid}), 201


@app.route('/target/<string:uid>', methods=['DELETE'])
def delete_target(uid):
    with open(BLACKBOX_FILE, 'r') as file:
        lines = file.readlines()

    updated_lines = []
    inside_targets_section = False

    for line in lines:
        stripped_line = line.strip()
        if stripped_line == "- targets:":
            inside_targets_section = True
            updated_lines.append(line)
            continue

        if inside_targets_section:
            uid_match = re.search(r'#UID (\S+)', stripped_line)
            if uid_match and uid_match.group(1) == uid:
                continue  # Skip this target

        updated_lines.append(line)

    with open(BLACKBOX_FILE, 'w') as file:
        file.writelines(updated_lines)

    return jsonify({"message": "Target deleted successfully"})


@app.route('/target/<string:uid>/toggle', methods=['POST'])
def toggle_target(uid):
    toggle_target_in_file(uid)
    return jsonify({"message": f"Target {uid} toggled successfully"})



if __name__ == '__main__':
    app.run(debug=True)