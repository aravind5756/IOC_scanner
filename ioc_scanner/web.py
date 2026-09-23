"""Flask application for the IOC scanner web interface."""

from dataclasses import asdict
from pathlib import Path
from tempfile import NamedTemporaryFile

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from .detections import (
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from .engine import (
    ScanStats,
    classify_ipv4,
    load_allowlist,
    load_patterns,
    scan_file,
)
from .reporting import collect_scan_metadata

MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".log", ".txt"}
DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_FAILED_LOGIN_WINDOW = 5


def parse_positive_integer(value: str | None) -> int | None:
    """Parse a positive whole number submitted by a web form."""
    try:
        number = int(value) if value is not None else 0
    except ValueError:
        return None
    return number if number >= 1 else None


def create_app() -> Flask:
    """Create and configure the IOC scanner web application."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

    @app.get("/")
    def index():
        """Display the IOC scanner home page."""
        return render_template("index.html")

    @app.get("/health")
    def health():
        """Report whether the web application is running."""
        return jsonify(status="ok")

    @app.post("/scan")
    def scan_upload():
        """Scan an uploaded log file and return its findings as JSON."""
        if "log_file" not in request.files:
            return jsonify(error="No log file was provided."), 400

        uploaded_file = request.files["log_file"]
        if not uploaded_file.filename:
            return jsonify(error="No log file was selected."), 400

        extension = Path(uploaded_file.filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify(error="Only .log and .txt files are supported."), 400

        failed_login_threshold = parse_positive_integer(
            request.form.get(
                "failed_login_threshold", str(DEFAULT_FAILED_LOGIN_THRESHOLD)
            )
        )
        if failed_login_threshold is None:
            return jsonify(
                error="The failed-login threshold must be a whole number of at least 1."
            ), 400

        failed_login_window = parse_positive_integer(
            request.form.get(
                "failed_login_window", str(DEFAULT_FAILED_LOGIN_WINDOW)
            )
        )
        if failed_login_window is None:
            return jsonify(
                error="The failed-login window must be a whole number of at least 1 minute."
            ), 400

        with NamedTemporaryFile(delete=False, suffix=extension) as temporary_file:
            uploaded_file.save(temporary_file)
            temporary_path = Path(temporary_file.name)

        try:
            patterns = load_patterns()
            allowlist = load_allowlist()
            metadata = collect_scan_metadata(
                temporary_path, display_name=uploaded_file.filename
            )
            with temporary_path.open("r") as log_file:
                log_lines = log_file.readlines()

            detection_settings = {
                "threshold": failed_login_threshold,
                "window_minutes": failed_login_window,
            }
            alerts = detect_repeated_failed_logins(log_lines, **detection_settings)
            alerts.extend(
                detect_success_after_failed_logins(log_lines, **detection_settings)
            )

            stats = ScanStats()
            findings = []

            for line_number, ioc_type, value, context in scan_file(
                str(temporary_path), patterns, stats, allowlist
            ):
                finding = {
                    "type": ioc_type,
                    "value": value,
                    "line_number": line_number,
                    "context": context,
                }
                if ioc_type == "ipv4":
                    finding["network_scope"] = classify_ipv4(value)
                findings.append(finding)
        except UnicodeDecodeError:
            return jsonify(error="The uploaded file must contain plain text."), 400
        finally:
            temporary_path.unlink(missing_ok=True)

        return jsonify(
            file=uploaded_file.filename,
            metadata=asdict(metadata),
            summary={
                "lines_scanned": stats.lines_scanned,
                "total_findings": stats.total_findings,
                "allowlisted_findings": stats.allowlisted_findings,
                "total_alerts": len(alerts),
                "failed_login_threshold": failed_login_threshold,
                "failed_login_window_minutes": failed_login_window,
                "findings_by_type": dict(sorted(stats.findings_by_type.items())),
                "allowlisted_by_type": dict(
                    sorted(stats.allowlisted_by_type.items())
                ),
            },
            findings=findings,
            alerts=[asdict(alert) for alert in alerts],
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(error):
        """Return a clear response when an upload exceeds the size limit."""
        return jsonify(error="The uploaded file must be 5 MB or smaller."), 413

    return app


app = create_app()
