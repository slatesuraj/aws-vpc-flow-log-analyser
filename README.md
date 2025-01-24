# VPC Flow Log Analyzer Web Application

## Overview
A powerful web application for analyzing AWS VPC Flow Logs, providing detailed network traffic insights and security group recommendations.

## Features
- Interactive web interface
- Detailed traffic summary
- Per-ENI security group rule suggestions
- Interactive traffic visualization
- Protocol and connection insights

## Prerequisites
- Python 3.8+
- pip

## Installation
1. Clone the repository
2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

## Running the Application
```bash
flask run
# Or
python app.py
```

## Usage
1. Export VPC Flow Logs from AWS Console
2. Upload the log file through the web interface
3. View comprehensive network traffic analysis

## Technologies
- Backend: Python, Flask, Pandas
- Frontend: Bootstrap, Plotly
- Visualization: Interactive Charts

## Security Considerations
- Always review suggested security group rules
- Use the suggestions as a starting point for configuration

## Contributing
Contributions are welcome! Please submit pull requests or open issues on GitHub.

## License
Apache License 2.0
