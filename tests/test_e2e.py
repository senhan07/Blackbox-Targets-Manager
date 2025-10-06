import pytest
from playwright.sync_api import Page, expect
import re
import os
import tempfile
from main import app as flask_app
from database import Database
from werkzeug.security import generate_password_hash

@pytest.fixture(scope="session")
def app():
    """Session-wide test Flask application."""
    db_fd, db_path = tempfile.mkstemp()

    flask_app.config.update({
        "TESTING": True,
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

    yield flask_app

    os.close(db_fd)
    os.unlink(db_path)

def test_e2e_flow(live_server, page: Page):
    """
    This test verifies the entire frontend flow in a clean, realistic environment.
    """
    base_url = live_server.url()

    # --- Admin Verification ---
    page.goto(f"{base_url}/login")
    page.get_by_placeholder("Username").fill("admin")
    page.get_by_placeholder("Password").fill("admin")
    page.get_by_role("button", name="Login").click()

    page.wait_for_url(re.compile(f".*/force-change-password"))

    expect(page.get_by_role("heading", name="Change Your Default Password")).to_be_visible()
    page.get_by_placeholder("New Password").fill("new_password")
    page.get_by_placeholder("Confirm Password").fill("new_password")
    page.get_by_role("button", name="Update Password").click()

    expect(page.get_by_text("Password updated successfully!")).to_be_visible()
    page.wait_for_url(f"{base_url}/")

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