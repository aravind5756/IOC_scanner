"""Flask application for the IOC scanner web interface."""

from flask import Flask, jsonify, render_template


def create_app() -> Flask:
    """Create and configure the IOC scanner web application."""
    app = Flask(__name__)

    @app.get("/")
    def index():
        """Display the IOC scanner home page."""
        return render_template("index.html")

    @app.get("/health")
    def health():
        """Report whether the web application is running."""
        return jsonify(status="ok")

    return app


app = create_app()
