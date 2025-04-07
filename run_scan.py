import requests
import time
import logging
import json
import uuid
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BURP_URL = "" # URL to your Burp server in the format <PROTOCOL>://<BURP_HOST> without a trailing slash
API_KEY = "" # API key generated through Burp with the create site and create scan permissions 

SITE_NAME = "" # This is the name of the site that will be shown in Burp
SITE_URL="" # The URL of the site to scan
SCAN_CONFIGURATION_IDS = ["13467384-a8c8-49f9-8d45-68e70e3e8776"] # This is lightweight. You can get the configuration ID by going to settings -> "Scan configurations" -> clicking the configuration -> the UUID at the end of the URL

GRAPHQL_ENDPOINT = f"{BURP_URL}/graphql/v1"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def execute_graphql_query(query, variables={}):
    """Helper function to execute GraphQL queries."""
    response = requests.post(GRAPHQL_ENDPOINT, json={"query": query, "variables": variables}, headers=HEADERS)
    
    logging.debug("------------------------------------------------")
    logging.debug("          GraphQL debug information             ")
    logging.debug("------------------------------------------------")      
    logging.debug(f"Query: {query}")
    logging.debug(f"Variables: {json.dumps(variables, indent=1)}")
    logging.debug(f"Response: {json.dumps(response.json(), indent=1)}")
    logging.debug("------------------------------------------------")

    if response.status_code != 200:
        fail(f"GraphQL query failed with status code: {response.status_code} and body {response.text}")
        response.raise_for_status()
        
    return response.json()

def create_site():
    """Creates a site and returns its ID."""
    logging.info(f"Creating site: {SITE_NAME}")
    query = """
    mutation CreateSite($input: CreateSiteInput!) {
        create_site(input: $input) {
            site {
                name 
                id
                scope_v2 { 
                    start_urls
                    in_scope_url_prefixes 
                    out_of_scope_url_prefixes 
                    protocol_options 
                } 
            }
        }
    }
    """
    variables = {
        "input": {
            "name": SITE_NAME,
            "parent_id": 0,
            "scope_v2": {
                "start_urls": [SITE_URL] if isinstance(SITE_URL, str) else SITE_URL,
                "protocol_options": "USE_HTTP_AND_HTTPS"
            },
            "confirm_permission_to_scan": True,
            "scan_configuration_ids": SCAN_CONFIGURATION_IDS,
            "application_logins": {}
        }
    }
    response = execute_graphql_query(query, variables)
    site_id = response["data"]["create_site"]["site"]["id"]
    logging.info(f"Site created with ID: {site_id}")
    return site_id

def start_scan(site_id):
    """Starts a scan and returns the scan ID."""
    logging.info(f"Starting scan for site ID: {site_id}")
    query = """
    mutation StartScan($input: CreateScheduleItemInput!) {
        create_schedule_item(input: $input) {
            schedule_item {
                id
            }
        }
    }
    """
    variables = {
        "input": {
            "site_id": site_id,
            "verbose_debug": None
        }
    }
    response = execute_graphql_query(query, variables)
    schedule_item_id = response["data"]["create_schedule_item"]["schedule_item"]["id"]
  
    query = """
    query GetScan($schedule_item_id: ID) {
        scans(limit: 1, schedule_item_id: $schedule_item_id) { 
            id 
        } 
    }
    """

    variables = {
        "schedule_item_id": schedule_item_id
    }

    response = execute_graphql_query(query, variables)
    scan_id = response["data"]["scans"][0]["id"]

    logging.info(f"Scan started - view the scan at {BURP_URL}/scans/{scan_id}")
  
    return scan_id

def wait_for_scan_completion(scan_id):
    """Polls the scan status until completion."""
    logging.info(f"Waiting for scan with schedule ID: {scan_id} to complete...")
    query = """
    query GetScan($id: ID!) {
        scan(id: $id) { 
            status 
        }
    }
    """

    variables = {
        "id": scan_id,
    }

    scan_ongoing = True

    while scan_ongoing:
        response = execute_graphql_query(query, variables)
        status = response["data"]["scan"]["status"]
                
        if status in ["failed", "cancelled"]:
            fail(f"Scan finished with status {status}")
        elif status == "succeeded":
            logging.info(f"Scan {scan_id} completed with status: {status}")
            scan_ongoing = False
        else:
            time.sleep(60)


def get_scan_results(scan_id):
    """Fetches and processes scan results."""
    logging.info(f"Fetching scan results with schedule ID: {scan_id}")
    query = """
    query GetScan($id: ID!) {
        scan(id: $id) { 
            issues(start: 0, count: 2147483647) {
                issue_type {
                    name
                }
                severity
                confidence
                path
            } 
        } 
    }
    """

    variables = {
        "id": scan_id,
    }

    response = execute_graphql_query(query, variables)
    issues = response["data"]["scan"]["issues"]

    # Grouping results logically
    grouped_issues = {}
    for issue in issues:
        severity = issue["severity"]
        if severity not in grouped_issues:
            grouped_issues[severity] = []
        grouped_issues[severity].append(issue)

    logging.info("Scan results:")
    for severity, issues in grouped_issues.items():
        logging.info(f"Severity: {severity}")
        for issue in issues:
            logging.info(f"- Issue Type: {issue['issue_type']['name']}, Path: {issue['path']}, Confidence: {issue['confidence']}")

def fail(message):
    logging.error(f"Fatal error - exiting: {message}")
    sys.exit(1)

def main():
    site_id = create_site()
    scan_id = start_scan(site_id)
    wait_for_scan_completion(scan_id)
    get_scan_results(scan_id)

if __name__ == "__main__":
    main()