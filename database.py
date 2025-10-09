import sqlite3
from datetime import datetime
import re

class Database:
    def __init__(self, db_file="blackbox.db"):
        self.db_file = db_file
        self.init_db()
        self.temp_targets = []
        self.temp_changes = {
            'added': [],
            'deleted': [],
            'toggled': [],
            'edited': []
        }
        self.load_targets_to_temp()

    def check_duplicate_addresses(self, addresses):
        """Check if any of the provided addresses already exist in the database"""
        if not addresses:
            return []

        existing_addresses = []
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(addresses))
            cursor.execute(f'SELECT instance FROM targets WHERE instance IN ({placeholders})', addresses)
            existing_addresses = [row[0] for row in cursor.fetchall()]

        temp_addresses = [target['instance'] for target in self.temp_targets
                        if target['id'] > 0 or target['id'] in self.temp_changes['added']]
        existing_addresses.extend([addr for addr in temp_addresses if addr in addresses])

        return list(set(existing_addresses))

    def init_db(self):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    instance TEXT NOT NULL,
                    module TEXT NOT NULL,
                    zone TEXT,
                    service TEXT,
                    device_type TEXT,
                    connection_type TEXT,
                    location TEXT,
                    short_name TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer'
                )
            ''')

            # Add columns if they don't exist for backward compatibility
            columns = [
                ('password_changed', 'INTEGER DEFAULT 0'),
                ('is_enabled', 'INTEGER DEFAULT 1')
            ]

            for column, definition in columns:
                try:
                    cursor.execute(f'ALTER TABLE users ADD COLUMN {column} {definition}')
                except sqlite3.OperationalError:
                    pass # Column already exists

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    yaml_endpoint_enabled INTEGER DEFAULT 1,
                    yaml_endpoint_path TEXT DEFAULT '/raw-yaml',
                    idle_timeout_minutes INTEGER DEFAULT 15,
                    prometheus_address TEXT DEFAULT 'http://prometheus:9090'
                )
            ''')

            # Ensure a default settings row exists
            cursor.execute('INSERT OR IGNORE INTO settings (id) VALUES (1)')

            # Add prometheus_address column if it doesn't exist
            try:
                cursor.execute("ALTER TABLE settings ADD COLUMN prometheus_address TEXT DEFAULT 'http://prometheus:9090'")
            except sqlite3.OperationalError:
                pass # Column already exists

            conn.commit()

    def get_all_users(self):
        """Get all users from the database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, role, is_enabled FROM users')
            return [dict(row) for row in cursor.fetchall()]

    def create_user(self, username, password, role='viewer', is_default_admin=False):
        """Create a new user"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            try:
                password_changed = 0 if is_default_admin else 1
                cursor.execute(
                    'INSERT INTO users (username, password, role, password_changed) VALUES (?, ?, ?, ?)',
                    (username, password, role, password_changed)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def delete_user(self, user_id):
        """Delete a user by their ID"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_user_by_username(self, username):
        """Get a user by their username"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cursor.fetchone()

    def get_user_by_id(self, user_id):
        """Get a user by their ID"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            return cursor.fetchone()

    def update_user_password(self, user_id, new_password):
        """Update a user's password and set the password_changed flag"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET password = ?, password_changed = 1 WHERE id = ?',
                (new_password, user_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def update_user_role(self, user_id, new_role):
        """Update a user's role"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            conn.commit()
            return cursor.rowcount > 0

    def toggle_user_status(self, user_id):
        """Toggle the is_enabled status of a user"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_enabled = NOT is_enabled WHERE id = ?', (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    def add_target(self, target_data):
        """Add target to temporary storage"""
        temp_id = -len(self.temp_changes['added']) - 1
        new_target = {
            'id': temp_id,
            'address': target_data['address'],
            'instance': target_data['instance'],
            'module': target_data['module'],
            'zone': target_data['zone'],
            'service': target_data['service'],
            'device_type': target_data['device_type'],
            'connection_type': target_data['connection_type'],
            'location': target_data['location'],
            'short_name': target_data['short_name'],
            'enabled': 1
        }
        self.temp_targets.append(new_target)
        self.temp_changes['added'].append(new_target)
        return temp_id

    def edit_target(self, id, target_data):
        """Edit target in temporary storage"""
        for target in self.temp_targets:
            if target['id'] == id:
                target.update(target_data)
                if id > 0 and id not in self.temp_changes['edited']:
                    self.temp_changes['edited'].append(id)
                return True
        return False

    def get_all_targets(self, use_temp=True):
        """Get all targets from storage"""
        if use_temp:
            return self.temp_targets

        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM targets')
            return [dict(row) for row in cursor.fetchall()]

    def get_target_by_id(self, target_id):
        """Get a single target by its ID from the main database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM targets WHERE id = ?', (target_id,))
            target = cursor.fetchone()
            return dict(target) if target else None

    def delete_target(self, id):
        """Delete target in temporary storage"""
        for i, target in enumerate(self.temp_targets):
            if target['id'] == id:
                if id > 0:
                    self.temp_changes['deleted'].append(id)
                self.temp_targets.pop(i)
                return True
        return False

    def hard_delete_target(self, target_id):
        """Permanently delete a target from the database"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
            conn.commit()
            return cursor.rowcount > 0

    def load_targets_to_temp(self):
        """Load all targets from database to temporary storage"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM targets')
            self.temp_targets = [dict(row) for row in cursor.fetchall()]
            self.temp_changes = {'added': [], 'deleted': [], 'toggled': [], 'edited': []}

    def toggle_target(self, id):
        """Toggle target in temporary storage"""
        for target in self.temp_targets:
            if target['id'] == id:
                target['enabled'] = not target['enabled']
                if id not in self.temp_changes['toggled']:
                    self.temp_changes['toggled'].append(id)
                return True
        return False

    def bulk_action(self, action, target_ids):
        """Perform a bulk action (enable, disable, remove) on selected targets."""
        for target_id in target_ids:
            if action == 'remove':
                self.delete_target(target_id)
            else:
                for target in self.temp_targets:
                    if target['id'] == target_id:
                        new_state = 1 if action == 'enable' else 0
                        if target['enabled'] != new_state:
                            target['enabled'] = new_state
                            if target_id not in self.temp_changes['toggled']:
                                self.temp_changes['toggled'].append(target_id)
                        break
        return True

    def save_changes(self):
        """Save all temporary changes to database and generate YAML"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            for id in self.temp_changes['deleted']:
                cursor.execute('DELETE FROM targets WHERE id = ?', (id,))

            for id in self.temp_changes['toggled']:
                for target in self.temp_targets:
                    if target['id'] == id:
                        cursor.execute('''
                            UPDATE targets
                            SET enabled = ?
                            WHERE id = ?
                        ''', (1 if target['enabled'] else 0, id))

            for id in self.temp_changes['edited']:
                for target in self.temp_targets:
                    if target['id'] == id:
                        cursor.execute('''
                            UPDATE targets
                            SET address = ?, instance = ?, module = ?, zone = ?, service = ?,
                                device_type = ?, connection_type = ?, location = ?, short_name = ?
                            WHERE id = ?
                        ''', (
                            target['address'], target['instance'], target['module'], target['zone'],
                            target['service'], target['device_type'], target['connection_type'],
                            target['location'], target['short_name'], id
                        ))

            for target in self.temp_changes['added']:
                cursor.execute('''
                    INSERT INTO targets (
                        address, instance, module, zone, service,
                        device_type, connection_type, location,
                        short_name, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    target['address'],
                    target['instance'],
                    target['module'],
                    target['zone'],
                    target['service'],
                    target['device_type'],
                    target['connection_type'],
                    target['location'],
                    target['short_name'],
                    target['enabled']
                ))

            conn.commit()

        self.load_targets_to_temp()
        return True

    def discard_changes(self):
        """Discard all temporary changes"""
        self.load_targets_to_temp()
        return True

    def get_filtered_targets(self, filters):
        """Get targets based on a list of filters with OR logic"""
        targets = self.get_all_targets()
        if not filters:
            return targets

        filtered_targets = []
        for target in targets:
            for f in filters:
                field = f['field']
                operator = f['operator']
                value = f['value']

                if field not in target:
                    continue

                target_value = str(target[field])

                match = False
                if operator == '==' and target_value == value:
                    match = True
                elif operator == '!=' and target_value != value:
                    match = True
                elif operator == '~=':
                    try:
                        if re.search(value, target_value, re.IGNORECASE):
                            match = True
                    except re.error:
                        # Ignore invalid regex patterns
                        pass

                if match:
                    filtered_targets.append(target)
                    break # Move to the next target once one filter matches (OR logic)

        return filtered_targets

    def get_settings(self):
        """Get the application settings"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM settings WHERE id = 1')
            settings = cursor.fetchone()
            return dict(settings) if settings else None

    def update_settings(self, settings_data):
        """Update the application settings"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE settings
                SET yaml_endpoint_enabled = ?,
                    yaml_endpoint_path = ?,
                    idle_timeout_minutes = ?,
                    prometheus_address = ?
                WHERE id = 1
            ''', (
                settings_data['yaml_endpoint_enabled'],
                settings_data['yaml_endpoint_path'],
                settings_data['idle_timeout_minutes'],
                settings_data['prometheus_address']
            ))
            conn.commit()
            return cursor.rowcount > 0

    def generate_yaml_content(self):
        targets = self.get_all_targets()
        yaml_lines = ["- targets:"]

        for target in targets:
            target_line = f"  {'# ' if not target['enabled'] else ''}- {target['address']};{target['instance']};" \
                         f"{target['module']};{target['zone']};{target['service']};{target['device_type']};" \
                         f"{target['connection_type']};{target['location']};" \
                         f"{target['short_name']}"
            yaml_lines.append(target_line)

        return "\n".join(yaml_lines)