import pytest
import os
import tempfile

import pytest

from server import create_app, db
from server.models import Upload, User, Tag
from server.testconfig import TestConfig

@pytest.fixture
def client():
    test_email = 'tina'
    test_password='melanka'
    app = create_app(TestConfig)
    client = app.test_client()
    with app.app_context():
        db.create_all()
        hashed_password = User.hash(test_password)
        print('hashed_password',hashed_password)
        user1 = User( username="tinochka", email=test_email,password=hashed_password)
        db.session.add(user1)
        db.session.commit()
        yield client