"""Flask application for the IOC scanner web interface."""

from flask import Flask, jsonify


def create_app() -> Flask:
    """Create and configure the IOC scanner web application."""
    app = Flask(__name__)

    @app.get("/health")
    def health():
        """Report whether the web application is running."""
        return jsonify(status="ok")

    return app


app = create_app()
