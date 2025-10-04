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
    response = client.post('/login', data={'username': 'testuser', 'password': 'password'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Blackbox Targets Manager' in response.data
    assert b'Logout' in response.data

    # Test logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data

def test_login_invalid_credentials(client):
    """Test login with invalid credentials."""
    response = client.post('/login', data={'username': 'wronguser', 'password': 'wrongpassword'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data

def test_index_unauthorized(client):
    """Test that the index page requires login."""
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data

def test_force_password_change(client):
    """Test that the default admin is forced to change password."""
    response = client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Change Your Default Password' in response.data

    # Test that other pages are not accessible
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Change Your Default Password' in response.data

    # Test changing the password
    response = client.post('/force-change-password', data={'new_password': 'newpassword', 'confirm_password': 'newpassword'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Password updated successfully!' in response.data
    assert b'Blackbox Targets Manager' in response.data