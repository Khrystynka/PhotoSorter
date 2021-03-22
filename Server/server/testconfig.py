from server.config import BaseConfig

class TestConfig(BaseConfig):
    print('Inside Test Config')
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'