import pytest
import sqlite3
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import main
from database import Database
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    # Create a temporary file to be used as the test database
    db_fd, db_path = tempfile.mkstemp()

    app = main.app
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_FILE": db_path,
    })

    # Create a new database instance for testing and monkeypatch the main.db
    main.db = Database(app.config['DATABASE_FILE'])

    with app.test_client() as client:
        with app.app_context():
            # Seed the test database
            main.db.create_user('testuser', generate_password_hash('password'), 'viewer')
            main.db.create_user('admin', generate_password_hash('admin'), 'admin', is_default_admin=True)
        yield client

    # Clean up the temporary database file
    os.close(db_fd)
    os.unlink(db_path)

def test_login_page(client):
    """Test that the login page loads correctly."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

def test_login_logout(client):
    """Test login and logout functionality."""
    # Test successful login
    response = client.post('/login', data={'username': 'testuser', 'password': 'password'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['redirect'] == '/'

    # Test that a session is created
    with client.session_transaction() as session:
        assert session.get('user_id') is not None

    # Test logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data
    with client.session_transaction() as session:
        assert session.get('user_id') is None

def test_login_invalid_credentials(client):
    """Test login with invalid credentials."""
    response = client.post('/login', data={'username': 'wronguser', 'password': 'wrongpassword'})
    assert response.status_code == 401
    json_data = response.get_json()
    assert 'Invalid username or password' in json_data['error']

def test_index_unauthorized(client):
    """Test that the index page requires login."""
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data

def test_force_password_change(client):
    """Test that the default admin is forced to change password."""
    # Login as default admin
    response = client.post('/login', data={'username': 'admin', 'password': 'admin'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['redirect'] == '/force-change-password'

    # Test that other pages redirect to force password change
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Change Your Default Password' in response.data

    # Test changing the password
    response = client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'Password updated successfully!' in json_data['message']

    # Follow redirect to ensure it goes to the main page
    response = client.get(json_data['redirect'], follow_redirects=True)
    assert response.status_code == 200
    assert b'Blackbox Targets Manager' in response.data

def test_create_user(client):
    """Test creating a new user."""
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'})
    response = client.post('/users/create', data={'username': 'newuser', 'password': 'password', 'role': 'viewer'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'User created successfully!' in json_data['message']

def test_user_enable_disable(client):
    """Test that a user can be enabled and disabled."""
    # Log in as admin and change password
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'})

    # Create a new user
    client.post('/users/create', data={'username': 'newuser', 'password': 'password', 'role': 'viewer'})

    # Disable the new user
    users = main.db.get_all_users()
    new_user = next((user for user in users if user['username'] == 'newuser'), None)
    client.post(f'/users/toggle-status/{new_user["id"]}')

    # Logout
    client.get('/logout')

    # Try to log in as disabled user
    response = client.post('/login', data={'username': 'newuser', 'password': 'password'})
    assert response.status_code == 403
    json_data = response.get_json()
    assert 'User is disabled' in json_data['error']

    # Log in as admin and re-enable the user
    client.post('/login', data={'username': 'admin', 'password': 'newpassword'})
    client.post(f'/users/toggle-status/{new_user["id"]}')

    # Logout
    client.get('/logout')

    # Try to log in as the re-enabled user
    response = client.post('/login', data={'username': 'newuser', 'password': 'password'})
    assert response.status_code == 200

def test_delete_self(client):
    """Test that a user cannot delete themselves."""
    # Log in as admin and change password
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'})

    # Get admin user id
    users = main.db.get_all_users()
    admin_user = next((user for user in users if user['role'] == 'admin'), None)

    # Attempt to delete self
    response = client.post(f'/users/delete/{admin_user["id"]}')
    assert response.status_code == 403
    json_data = response.get_json()
    assert 'You cannot delete your own account' in json_data['error']

def test_delete_another_admin(client):
    """Test that an admin can delete another admin."""
    # Log in as admin and change password
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'})

    # Create admin2
    client.post('/users/create', data={'username': 'admin2', 'password': 'password', 'role': 'admin'})

    # Log in as admin2
    client.get('/logout')
    client.post('/login', data={'username': 'admin2', 'password': 'password'})

    # Get admin1's id
    users = main.db.get_all_users()
    admin1_user = next((user for user in users if user['username'] == 'admin'), None)

    # Delete admin1
    response = client.post(f'/users/delete/{admin1_user["id"]}')
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'User deleted successfully!' in json_data['message']

def test_raw_yaml_endpoint(client):
    """Test the /raw-yaml endpoint."""
    # Log in
    client.post('/login', data={'username': 'testuser', 'password': 'password'})

    # Generate the yaml file
    main.generate_yaml_file()

    # Access the endpoint
    response = client.get('/raw-yaml')
    assert response.status_code == 200
    assert b'- targets:' in response.data

def test_raw_yaml_not_found(client):
    """Test the /raw-yaml endpoint when the file is not found."""
    # Log in
    client.post('/login', data={'username': 'testuser', 'password': 'password'})

    # Ensure the file doesn't exist
    if os.path.exists(main.app.config['BLACKBOX_FILE']):
        os.remove(main.app.config['BLACKBOX_FILE'])

    response = client.get('/raw-yaml')
    assert response.status_code == 404
    assert b'YAML file not found' in response.data