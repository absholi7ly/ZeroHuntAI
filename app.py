#!/usr/bin/env python3
"""
ZeroHuntAI - AI-powered Vulnerability Scanner
======================================================

Web interface for ZeroHuntAI
"""

import os
import time
import tempfile
import json
import os.path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SelectField, BooleanField, SubmitField, MultipleFileField
from wtforms.validators import DataRequired, Optional, URL
from werkzeug.utils import secure_filename

from scanner.local_scanner import LocalScanner
from scanner.github_scanner import GitHubScanner
from utils.logger import setup_logger, get_logger

# Set up the logger
setup_logger()
logger = get_logger()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "zerohuntai-secret-key")

# Custom filters
@app.template_filter('basename')
def basename_filter(path):
    """Get the base name of a file path."""
    return os.path.basename(path) if path else ""

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'js', 'php', 'java', 'c', 'cpp', 'go', 'rb', 'html', 'css', 'xml', 'json', 'yml', 'yaml', 'txt', 'md'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Forms
class ScanForm(FlaskForm):
    """Form for scanning options."""
    scan_mode = SelectField('Scan Mode', choices=[
        ('local', 'Upload Files'),
        ('github', 'GitHub Repository')
    ], validators=[DataRequired()])
    
    github_url = StringField('GitHub Repository URL', validators=[Optional(), URL()])
    
    files = MultipleFileField('Upload Files', validators=[Optional()])
    
    language_extensions = StringField('Language Extensions (comma-separated, e.g., py,js,php)', validators=[Optional()])
    
    enable_call_graph = BooleanField('Enable Call Graph Generation (Experimental)')
    scan_secrets = BooleanField('Scan for API Keys and Secrets')
    
    submit = SubmitField('Start Scan')

def allowed_file(filename):
    """Check if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_old_uploads():
    """Clean up old uploads (files older than 1 hour)."""
    try:
        current_time = time.time()
        for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
            for dirname in dirs:
                dir_path = os.path.join(root, dirname)
                # If directory is older than 1 hour
                if os.path.isdir(dir_path) and current_time - os.path.getmtime(dir_path) > 3600:
                    for file in os.listdir(dir_path):
                        os.remove(os.path.join(dir_path, file))
                    os.rmdir(dir_path)
    except Exception as e:
        logger.error(f"Error cleaning old uploads: {str(e)}")

@app.route('/')
def index():
    """Render the home page."""
    form = ScanForm()
    return render_template('index.html', form=form)

@app.route('/scan', methods=['POST'])
def scan():
    """Handle the scan form submission."""
    form = ScanForm()
    
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
        return redirect(url_for('index'))
    
    # Create a unique folder for this scan session
    session_id = str(int(time.time()))
    session['scan_id'] = session_id
    
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    output_dir = os.path.join('output', session_id)
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    # Get parameters
    scan_mode = form.scan_mode.data
    enable_call_graph = form.enable_call_graph.data
    scan_secrets = form.scan_secrets.data
    
    # Parse language extensions
    language_extensions = None
    if form.language_extensions.data:
        language_extensions = [f".{ext.strip()}" for ext in form.language_extensions.data.split(',')]
    
    try:
        if scan_mode == 'local':
            # Handle file uploads
            files = request.files.getlist('files')
            if not files or files[0].filename == '':
                flash("No files selected for scanning.", "danger")
                return redirect(url_for('index'))
            
            # Save uploaded files
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(upload_dir, filename)
                    file.save(file_path)
            
            # Create local scanner
            scanner = LocalScanner(
                upload_dir,
                output_dir=output_dir,
                language_extensions=language_extensions,
                verbose=True,
                scan_secrets=scan_secrets,
                enable_call_graph=enable_call_graph
            )
            
            # Store scan parameters in session
            session['scan_mode'] = 'local'
            session['scan_path'] = upload_dir
            session['output_dir'] = output_dir
            
        elif scan_mode == 'github':
            # Handle GitHub repository
            github_url = form.github_url.data
            if not github_url:
                flash("Please provide a GitHub repository URL.", "danger")
                return redirect(url_for('index'))
            
            # Create GitHub scanner
            scanner = GitHubScanner(
                github_url,
                output_dir=output_dir,
                language_extensions=language_extensions,
                verbose=True,
                scan_secrets=scan_secrets,
                enable_call_graph=enable_call_graph
            )
            
            # Store scan parameters in session
            session['scan_mode'] = 'github'
            session['repo_url'] = github_url
            session['output_dir'] = output_dir
        
        # Start scanning in a background thread
        # For simplicity, we'll do it synchronously here
        scan_result = scanner.scan()
        
        # Generate reports
        json_path = scanner.generate_report(format='json')
        html_path = scanner.generate_report(format='html')
        
        # Generate call graph if enabled
        graph_path = None
        if enable_call_graph:
            graph_path = scanner.generate_call_graph()
        
        # Store report paths in session
        session['json_report'] = json_path
        session['html_report'] = html_path
        session['call_graph'] = graph_path
        
        # Store scan results summary in session
        session['scan_summary'] = {
            'total_files': scan_result['stats']['total_files'],
            'high_severity': scan_result['stats']['high_severity'],
            'medium_severity': scan_result['stats']['medium_severity'],
            'low_severity': scan_result['stats']['low_severity'],
            'total_vulnerabilities': (
                scan_result['stats']['high_severity'] +
                scan_result['stats']['medium_severity'] +
                scan_result['stats']['low_severity']
            )
        }
        
        # Clean up old uploads
        clean_old_uploads()
        
        # Redirect to results page
        return redirect(url_for('results'))
        
    except Exception as e:
        logger.exception("Error during scanning")
        flash(f"Error during scanning: {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/results')
def results():
    """Show scan results."""
    # Check if we have scan results
    if 'scan_summary' not in session:
        flash("No scan results available. Please run a scan first.", "warning")
        return redirect(url_for('index'))
    
    # Load scan summary
    scan_summary = session['scan_summary']
    
    # Determine what to show
    scan_mode = session.get('scan_mode')
    scan_target = session.get('repo_url') if scan_mode == 'github' else 'Uploaded Files'
    
    # Get report paths
    html_report = session.get('html_report')
    json_report = session.get('json_report')
    call_graph = session.get('call_graph')
    
    # Load vulnerability details from JSON report
    vulnerabilities = []
    try:
        if json_report and os.path.exists(json_report):
            with open(json_report, 'r') as f:
                report_data = json.load(f)
                vulnerabilities = report_data.get('vulnerabilities', [])
    except Exception as e:
        logger.error(f"Error loading vulnerability details: {str(e)}")
    
    return render_template(
        'results.html',
        scan_summary=scan_summary,
        scan_mode=scan_mode,
        scan_target=scan_target,
        html_report=html_report,
        json_report=json_report,
        call_graph=call_graph,
        vulnerabilities=vulnerabilities
    )

@app.route('/download/<file_type>')
def download_report(file_type):
    """Download a report file."""
    if file_type == 'json' and 'json_report' in session:
        return send_file(session['json_report'], as_attachment=True)
    elif file_type == 'html' and 'html_report' in session:
        return send_file(session['html_report'], as_attachment=True)
    elif file_type == 'call_graph' and 'call_graph' in session:
        return send_file(session['call_graph'], as_attachment=True)
    else:
        flash("The requested file is not available.", "danger")
        return redirect(url_for('results'))

@app.route('/view/<file_type>')
def view_report(file_type):
    """View a report file in the browser."""
    if file_type == 'html' and 'html_report' in session:
        # Serve the HTML report
        with open(session['html_report'], 'r') as f:
            report_content = f.read()
        return report_content
    elif file_type == 'call_graph' and 'call_graph' in session:
        # Serve the call graph visualization
        with open(session['call_graph'], 'r') as f:
            graph_content = f.read()
        return graph_content
    else:
        flash("The requested file is not available.", "danger")
        return redirect(url_for('results'))

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint to get vulnerability data for filtering/sorting in the UI."""
    # Load vulnerability details from JSON report
    vulnerabilities = []
    try:
        if 'json_report' in session and os.path.exists(session['json_report']):
            with open(session['json_report'], 'r') as f:
                report_data = json.load(f)
                vulnerabilities = report_data.get('vulnerabilities', [])
    except Exception as e:
        logger.error(f"Error loading vulnerability details: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)