import pytest
from playwright.sync_api import Page, expect
import re
import os
import tempfile
from main import app as flask_app
from database import Database
from werkzeug.security import generate_password_hash
<<<<<<< HEAD
<<<<<<< HEAD

@pytest.fixture(scope="session")
def app():
    """Session-wide test Flask application."""
=======
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
from _pytest.monkeypatch import MonkeyPatch
import sqlite3

@pytest.fixture(scope='session')
def session_monkeypatch():
    """Session-scoped monkeypatch."""
    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()

@pytest.fixture(scope="session")
def app(session_monkeypatch):
    """
    Session-wide test Flask application.
    Uses a session-scoped monkeypatch to replace the global 'db' object in 'main'
    with a temporary database for the test session.
    """
<<<<<<< HEAD
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
    db_fd, db_path = tempfile.mkstemp()

    flask_app.config.update({
        "TESTING": True,
<<<<<<< HEAD
<<<<<<< HEAD
        "WTF_CSRF_ENABLED": True,  # Enable CSRF for realistic testing
        "DATABASE_FILE": db_path,
        "SERVER_NAME": "127.0.0.1" # Let pytest-flask pick the port
    })

    db = Database(flask_app.config['DATABASE_FILE'])
    flask_app.db = db

    with flask_app.app_context():
        db.init_db()
        db.create_user('testuser', generate_password_hash('password'), 'viewer')
        db.create_user('admin', generate_password_hash('admin'), 'admin', is_default_admin=True)
=======
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
        "WTF_CSRF_ENABLED": True,
        "DATABASE_FILE": db_path,
        "SERVER_NAME": "127.0.0.1"
    })

    test_db = Database(flask_app.config['DATABASE_FILE'])

    session_monkeypatch.setattr('main.db', test_db)

    flask_app.db = test_db

    with flask_app.app_context():
        test_db.init_db()
<<<<<<< HEAD
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c

    yield flask_app

    os.close(db_fd)
    os.unlink(db_path)

<<<<<<< HEAD
<<<<<<< HEAD
def test_e2e_flow(live_server, page: Page):
    """
    This test verifies the entire frontend flow in a clean, realistic environment.
    """
    base_url = live_server.url()

    # --- Admin Verification ---
=======
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
@pytest.fixture(scope="function")
def clean_db(app):
    """Ensure the database is clean before each test function."""
    with app.app_context():
        db = app.db
        with sqlite3.connect(db.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users")
            cursor.execute("DELETE FROM targets")
            cursor.execute("DELETE FROM settings")
            cursor.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")
            conn.commit()

        # Recreate users and reset state
        db.create_user('testuser', generate_password_hash('password'), 'viewer')
        db.create_user('admin', generate_password_hash('admin'), 'admin', is_default_admin=True)
        db.load_targets_to_temp()
        app._got_first_request = False


def test_e2e_and_bug_fixes(live_server, page: Page, clean_db):
    """
    This test verifies the entire frontend flow and all the recent bug fixes.
    """
    base_url = live_server.url()

    # --- Login and Password Change ---
<<<<<<< HEAD
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
    page.goto(f"{base_url}/login")
    page.get_by_placeholder("Username").fill("admin")
    page.get_by_placeholder("Password").fill("admin")
    page.get_by_role("button", name="Login").click()

    page.wait_for_url(re.compile(f".*/force-change-password"))
<<<<<<< HEAD
<<<<<<< HEAD

    expect(page.get_by_role("heading", name="Change Your Default Password")).to_be_visible()
    page.get_by_placeholder("New Password").fill("new_password")
    page.get_by_placeholder("Confirm Password").fill("new_password")
=======
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
    expect(page.get_by_role("heading", name="Change Your Default Password")).to_be_visible()

    # Use exact=True to resolve ambiguity
    page.get_by_label("New Password", exact=True).fill("new_password")
    page.get_by_label("Confirm New Password", exact=True).fill("new_password")
<<<<<<< HEAD
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
    page.get_by_role("button", name="Update Password").click()

    expect(page.get_by_text("Password updated successfully!")).to_be_visible()
    page.wait_for_url(f"{base_url}/")

<<<<<<< HEAD
<<<<<<< HEAD
    expect(page.get_by_role("heading", name="Blackbox Targets Manager")).to_be_visible()

    # 1. Verify User Dropdown (Admin)
    user_dropdown_button = page.locator(".user-button", has_text="admin")
    expect(user_dropdown_button).to_be_visible()
    user_dropdown_button.click()
    page.screenshot(path="jules-scratch/verification/01_admin_dropdown.png")

    # 2. Verify Settings Page
    page.get_by_role("link", name="Settings").click()
    expect(page).to_have_url(f"{base_url}/settings")
    expect(page.get_by_role("heading", name="Settings")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/02_settings_page.png")

    # 3. Verify User Management Page
    page.goto(f"{base_url}/users")
    expect(page.get_by_role("heading", name="User Management")).to_be_visible()
    expect(page.locator(".user-card").first).to_be_visible()
    page.screenshot(path="jules-scratch/verification/03_user_management_page.png")

    # 4. Verify Export Modal
    page.goto(f"{base_url}/")
    user_dropdown_button = page.locator(".user-button", has_text="admin")
    user_dropdown_button.click()
    page.get_by_role("link", name="Export").click()
    expect(page.get_by_role("heading", name="Export Targets")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/04_export_modal.png")
    page.get_by_role("button", name="×").click()

    # 5. Logout
    page.get_by_role("link", name="Logout").click()
    expect(page).to_have_url(f"{base_url}/login")

    # --- Viewer Verification ---
    page.get_by_placeholder("Username").fill("testuser")
    page.get_by_placeholder("Password").fill("password")
    page.get_by_role("button", name="Login").click()
    expect(page).to_have_url(f"{base_url}/")
    expect(page.get_by_role("heading", name="Blackbox Targets Manager")).to_be_visible()

    # 6. Verify User Dropdown (Viewer) and Access Control
    viewer_dropdown_button = page.locator(".user-button", has_text="testuser")
    expect(viewer_dropdown_button).to_be_visible()
    viewer_dropdown_button.click()

    page.get_by_role("link", name="Settings").click()
    expect(page.get_by_text("Access Denied")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/05_viewer_access_denied.png")
=======
=======
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
    # --- Verify "No Data" Message ---
    expect(page.get_by_text("No targets found.")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/01_no_data_message.png")

    # --- Verify Settings Page UI ---
    page.locator(".user-button").click()
    page.get_by_role("link", name="Settings").click()
    expect(page).to_have_url(f"{base_url}/settings")
    expect(page.locator(".setting-card").first).to_be_visible()
    page.screenshot(path="jules-scratch/verification/02_settings_page_modern.png")

    # --- Verify Export Modal and its fixes ---
    page.goto(f"{base_url}/")
    page.locator(".user-button").click()
    page.get_by_role("link", name="Export").click()
    expect(page.get_by_role("heading", name="Export Targets")).to_be_visible()
    expect(page.locator(".preview-header")).to_be_visible()
    page.get_by_role("button", name="Add Filter").click()
    expect(page.locator(".filter-row")).to_have_count(1)
    page.screenshot(path="jules-scratch/verification/03_export_modal_fixed.png")
    page.get_by_role("button", name="×").click()
    expect(page.get_by_role("heading", name="Export Targets")).not_to_be_visible()

    # --- Verify Viewer Access Denied Toast Color ---
    page.get_by_role("link", name="Logout").click()
    page.wait_for_url(f"{base_url}/login")
    page.get_by_placeholder("Username").fill("testuser")
    page.get_by_placeholder("Password").fill("password")
    page.get_by_role("button", name="Login").click()
    page.wait_for_url(f"{base_url}/")

    page.locator(".user-button").click()
    page.get_by_role("link", name="Settings").click()

    toast = page.locator(".toast.error")
    expect(toast).to_be_visible()
    expect(toast).to_have_text("Access Denied: You do not have permission to view this page.")
    page.screenshot(path="jules-scratch/verification/04_access_denied_toast_red.png")

<<<<<<< HEAD
    print("All visual and functional verifications passed.")
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
=======
    print("All visual and functional verifications passed.")
>>>>>>> 53f13ebda89e6d6460280047d74ee3b7b91b3a8c
