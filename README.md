# BurPy

This project is a Python-based tool to automate web application security scans using Burp Suite's GraphQL API (called BurPy). It allows you to create a site, start a scan, monitor its progress, and retrieve the results programmatically.

## Features

- Create a site in Burp Suite with a specified scope.
- Start a scan for the created site.
- Monitor the scan's progress until completion.
- Retrieve and display scan results, grouped by severity.

## Requirements

- Python 3.8 or higher
- Burp Suite Enterprise with GraphQL API enabled
- API key with permissions to create sites and scans

## Running the script
### Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd graphql-run-scan
```

2. Create a virtual environment and activate it:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

### Configuration
Before running the script, update the following variables in `run_scan.py`:
- `BURP_URL`: The URL of your Burp Suite server
- `API_KEY`: Your Burp Suite API key
- `SITE_NAME`: The name of the site to be created in Burp Suite
- `SITE_URL`: The URL of the site to scan
- `SCAN_CONFIGURATION_IDS`: The scan configuration ID(s) to use

### Usage
```bash
python run_scan.py
```

## Logging
The script logs its progress and results to the console. You can adjust the logging level by modifying the `logging.basicConfig` configuration in `run_scan.py`.

## Notes
- Ensure that the Burp Suite server is accessible from the machine running this script.
- The API key must have the necessary permissions to create sites and scans.
