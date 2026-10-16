"""إعدادات اختبارات pytest."""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import create_app
from app.models import db
from app.models.user import User
from config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "test-admin-pass-123"
    ADMIN_EMAIL = "admin@test.local"
    DEBUG = False


@pytest.fixture()
def app():
    application = create_app(TestConfig)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(client, app):
    with app.app_context():
        # المستخدم يُنشأ عبر bootstrap
        pass
    client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-pass-123"},
        follow_redirects=True,
    )
    return client


@pytest.fixture()
def viewer_client(app):
    with app.app_context():
        u = User(username="viewer1", email="v@test.local", role="viewer")
        u.set_password("viewer-pass-123")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    c.post(
        "/login",
        data={"username": "viewer1", "password": "viewer-pass-123"},
        follow_redirects=True,
    )
    return c
