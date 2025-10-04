import sqlite3
from datetime import datetime

class Database:
    def __init__(self, db_file="blackbox.db"):
        self.db_file = db_file
        self.init_db()
        self.temp_targets = []
        self.temp_changes = {
            'added': [],
            'deleted': [],
            'toggled': []
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
                    role TEXT NOT NULL DEFAULT 'viewer',
                    password_changed INTEGER DEFAULT 0
                )
            ''')
            # Add password_changed column if it doesn't exist for backward compatibility
            try:
                cursor.execute('ALTER TABLE users ADD COLUMN password_changed INTEGER DEFAULT 0')
            except sqlite3.OperationalError:
                pass  # Column already exists
            conn.commit()

    def get_all_users(self):
        """Get all users from the database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, role FROM users')
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

    def get_all_targets(self, use_temp=True):
        """Get all targets from storage"""
        if use_temp:
            return self.temp_targets

        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM targets')
            return [dict(row) for row in cursor.fetchall()]

    def delete_target(self, id):
        """Delete target in temporary storage"""
        for i, target in enumerate(self.temp_targets):
            if target['id'] == id:
                if id > 0:
                    self.temp_changes['deleted'].append(id)
                self.temp_targets.pop(i)
                return True
        return False

    def load_targets_to_temp(self):
        """Load all targets from database to temporary storage"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM targets')
            self.temp_targets = [dict(row) for row in cursor.fetchall()]
            self.temp_changes = {'added': [], 'deleted': [], 'toggled': []}

    def toggle_target(self, id):
        """Toggle target in temporary storage"""
        for target in self.temp_targets:
            if target['id'] == id:
                target['enabled'] = not target['enabled']
                if id not in self.temp_changes['toggled']:
                    self.temp_changes['toggled'].append(id)
                return True
        return False

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