import pytest
from playwright.sync_api import Page, expect
import re
import os
import tempfile
from main import app as flask_app
from database import Database
from werkzeug.security import generate_password_hash
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
    db_fd, db_path = tempfile.mkstemp()

    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "DATABASE_FILE": db_path,
        "SERVER_NAME": "127.0.0.1"
    })

    test_db = Database(flask_app.config['DATABASE_FILE'])

    session_monkeypatch.setattr('main.db', test_db)

    flask_app.db = test_db

    with flask_app.app_context():
        test_db.init_db()

    yield flask_app

    os.close(db_fd)
    os.unlink(db_path)

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
    page.goto(f"{base_url}/login")
    page.get_by_placeholder("Username").fill("admin")
    page.get_by_placeholder("Password").fill("admin")
    page.get_by_role("button", name="Login").click()

    page.wait_for_url(re.compile(f".*/force-change-password"))
    expect(page.get_by_role("heading", name="Change Your Default Password")).to_be_visible()

    # Use exact=True to resolve ambiguity
    page.get_by_label("New Password", exact=True).fill("new_password")
    page.get_by_label("Confirm New Password", exact=True).fill("new_password")
    page.get_by_role("button", name="Update Password").click()

    expect(page.get_by_text("Password updated successfully!")).to_be_visible()
    page.wait_for_url(f"{base_url}/")

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

    print("All visual and functional verifications passed.")