import os
import io
import base64
import pandas as pd
import plotly
import plotly.graph_objs as go
import json
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from vpc_flow_analyzer import VPCFlowLogAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max file size
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],
    storage_uri="memory://"
)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'log'}

def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_traffic_plot(df, top_n=10):
    """
    Generate Plotly traffic visualization
    
    :param df: DataFrame with network traffic data
    :param top_n: Number of top ports to visualize
    :return: JSON-encoded Plotly figure
    """
    # Top source ports
    src_port_counts = df['srcport'].value_counts().head(top_n)
    src_port_trace = go.Bar(
        x=src_port_counts.index.astype(str), 
        y=src_port_counts.values, 
        name='Source Ports'
    )

    # Top destination ports
    dst_port_counts = df['dstport'].value_counts().head(top_n)
    dst_port_trace = go.Bar(
        x=dst_port_counts.index.astype(str), 
        y=dst_port_counts.values, 
        name='Destination Ports'
    )

    # Create the layout
    layout = go.Layout(
        title=f'Top {top_n} Source and Destination Ports',
        xaxis={'title': 'Port'},
        yaxis={'title': 'Connection Count'},
        barmode='group'
    )

    # Create figure
    fig = go.Figure(data=[src_port_trace, dst_port_trace], layout=layout)
    
    # Convert plot to JSON
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def upload_file():
    """
    Handle file upload and analysis
    """
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If no file selected
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Validate file
        if file and allowed_file(file.filename):
            # Secure filename and save
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Validate file size
                file_size = os.path.getsize(filepath)
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    os.remove(filepath)
                    flash(f'File too large. Maximum size is {app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)} MB', 'error')
                    return redirect(request.url)
                
                # Analyze VPC flow log
                analyzer = VPCFlowLogAnalyzer(filepath, chunk_size=50000)
                
                # Traffic summary
                summary = analyzer.summarize_traffic()
                
                # Security group suggestions
                security_suggestions = analyzer.generate_security_group_suggestions()
                
                # Generate traffic plot
                traffic_plot = generate_traffic_plot(analyzer.df)
                
                # Clean up uploaded file
                os.remove(filepath)
                
                return render_template(
                    'results.html', 
                    summary=summary,
                    security_suggestions=security_suggestions,
                    traffic_plot=traffic_plot
                )
            
            except Exception as e:
                # Clean up file in case of error
                if os.path.exists(filepath):
                    os.remove(filepath)
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(request.url)
        
        # Invalid file type
        flash('Invalid file type. Please upload .txt or .log files.', 'error')
        return redirect(request.url)
    
    return render_template('index.html')

@app.route('/about')
@limiter.limit("30 per minute")
def about():
    return render_template('about.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    """
    Handle rate limit exceeded errors
    """
    return render_template('ratelimit.html'), 429

if __name__ == '__main__':
    app.run(debug=True)
