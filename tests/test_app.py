import pytest
import sqlite3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app, db
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    client = app.test_client()

    with app.app_context():
        db.init_db()
        # Clean up users table before each test
        with sqlite3.connect(db.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users")
            conn.commit()
        db.create_user('testuser', generate_password_hash('password'), 'viewer')
        db.create_user('admin', generate_password_hash('admin'), 'admin', is_default_admin=True)

    yield client

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