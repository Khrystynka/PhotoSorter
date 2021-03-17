import pytest
import os
import tempfile

import pytest

from server import create_app, db
from server.models import Upload, User, Tag
from server.testconfig import TestConfig

@pytest.fixture
def client():
    app = create_app(TestConfig)
    client = app.test_client()
    with app.app_context():
        db.create_all()
        user1 = User( username="kestel white", email="kestel",password='white')
        db.session.add(user1)
        db.session.commit()
    yield client