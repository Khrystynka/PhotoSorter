from server import app
from server.config import BaseConfig


if __name__ == '__main__':
    app = create_app(BaseConfig)
    app.run(debug=True)
    # app = create_app()
    # app.run()
