"""
Central Flask Application for Distributed Cyberattack Detection and Alert System.
Entry point orchestrating blueprints, database connections, and SOC dashboard services.
"""
import os
from flask import Flask, render_template, session
from config import Config
from database.db import db
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.monitoring import monitoring_bp
from routes.alerts import alerts_bp
from routes.agents import agents_bp
from routes.reports import reports_bp
from routes.settings import settings_bp
from utils.logger import logger

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Database Schema & Data Seeding
    try:
        db.init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization warning: {e}")

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(agents_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    # Context Processors for Templates
    @app.context_processor
    def inject_global_data():
        return {
            'current_user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'full_name': session.get('full_name', 'Security Analyst'),
                'role': session.get('role', 'ANALYST')
            },
            'app_name': 'CYBER-SENTINEL IDS',
            'app_version': 'v2.6'
        }

    # Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('base.html', error_code=404, error_message="Resource not found."), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('base.html', error_code=500, error_message="Internal Security Engine error."), 500

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting Distributed Cyberattack Detection System on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)
