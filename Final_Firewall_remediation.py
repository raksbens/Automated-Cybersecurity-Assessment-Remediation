import requests
import json
from jinja2 import Template
import urllib3

# FortiGate API details
BASE_URL = "https://<Fortigate_firewall_ip_address>/api/v2/cmdb"
HEADERS = {'Authorization': 'Bearer <api_key>'}
CERT_PATH = r"C:\path\to\certificate.pem"

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTML template for the remediation report
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiGate Remediation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
        h1 { color: #333; }
        .remediated { color: green; }
        .no-remediation { color: orange; }
    </style>
</head>
<body>
    <h1>FortiGate Remediation Report</h1>
    
    <h2>Remediated Controls</h2>
    {% if remediated_policies %}
        <h3>Remediated Policies</h3>
        <ul>
        {% for policy in remediated_policies %}
            <li class="remediated">Policy {{ policy.name }} (ID: {{ policy.id }})</li>
        {% endfor %}
        </ul>
    {% endif %}

    {% if remediated_zones %}
        <h3>Remediated Zones</h3>
        <ul>
        {% for zone in remediated_zones %}
            <li class="remediated">Zone {{ zone.name }}</li>
        {% endfor %}
        </ul>
    {% endif %}

    {% if remediated_interfaces %}
        <h3>Remediated Interfaces</h3>
        <ul>
        {% for interface in remediated_interfaces %}
            <li class="remediated">Interface {{ interface.name }}</li>
        {% endfor %}
        </ul>
    {% endif %}

    {% if remediated_usb %}
        <h3>USB Auto-Install Settings Remediated</h3>
        <p class="remediated">USB auto-install configuration and image settings have been disabled.</p>
    {% endif %}

    {% if remediated_tls %}
        <h3>TLS Settings Remediated</h3>
        <p class="remediated">Static key ciphers for TLS have been disabled.</p>
    {% endif %}

    {% if not remediated_policies and not remediated_zones and not remediated_interfaces and not remediated_usb and not remediated_tls %}
        <p class="no-remediation">No controls were remediated.</p>
    {% endif %}
</body>
</html>
"""
def fetch_policies():
    try:
        response = requests.get(f"{BASE_URL}/firewall/policy", headers=HEADERS, verify=False)
        response.raise_for_status()
        policies = response.json().get('results', [])
        return policies
    except Exception as e:
        print(f"Error fetching policies: {str(e)}")
        return []
    
# Helper function to log request/response details
def log_request(endpoint, payload, response):
    print(f"\nRequest to: {endpoint}")
    print(f"Payload: {json.dumps(payload, indent=4)}")
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Text: {response.text}")

# Helper function to send PUT requests to update FortiGate configurations
def update_fortigate_config(endpoint, payload):
    try:
        url = f"{BASE_URL}{endpoint}"
        response = requests.put(url, headers=HEADERS, json=payload, verify=False)
        log_request(endpoint, payload, response)
        if response.status_code == 200:
            print(f"Successfully updated: {endpoint}")
        else:
            print(f"Failed to update {endpoint}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error during update: {str(e)}")

# Fetch available IP addresses for srcaddr and dstaddr selection
def fetch_ip_addresses():
    try:
        response = requests.get(f"{BASE_URL}/firewall/address", headers=HEADERS, verify=False)
        addresses = response.json().get('results', [])
        address_list = [(address['name'], address.get('subnet', 'Unknown subnet')) for address in addresses if 'name' in address and 'subnet' in address]
        return address_list
    except Exception as e:
        print(f"Error fetching IP addresses: {str(e)}")
        return []

# Fetch available services for service selection
def fetch_services():
    try:
        response = requests.get(f"{BASE_URL}/firewall.service/custom", headers=HEADERS, verify=False)
        services = response.json().get('results', [])
        return [service['name'] for service in services]
    except Exception as e:
        print(f"Error fetching services: {str(e)}")
        return []

# Remediate firewall policies
def remediate_policy():
    remediated_policies = []
    policies_endpoint = "/firewall/policy"
    response = requests.get(f"{BASE_URL}{policies_endpoint}", headers=HEADERS, verify=False)
    policies = response.json().get('results', [])

    # Fetch available IP addresses and services
    available_ips = fetch_ip_addresses()
    available_services = fetch_services()

    for policy in policies:
        updated = False

        # Remediate source and destination addresses
        if policy['srcaddr'][0]['name'] == 'all':
            print(f"Policy {policy['policyid']} has 'all' as source address")
            selected_src = available_ips[0][0]  # Automatically select first for web use
            policy['srcaddr'][0]['name'] = selected_src
            updated = True
        
        if policy['dstaddr'][0]['name'] == 'all':
            print(f"Policy {policy['policyid']} has 'all' as destination address")
            selected_dst = available_ips[0][0]  # Automatically select first for web use
            policy['dstaddr'][0]['name'] = selected_dst
            updated = True
        
        # Remediate services
        if policy['service'][0]['name'] in ['ALL', 'ALL_TCP', 'ALL_ICMP', 'ALL_UDP', 'ALL_ICMP6']:
            print(f"Policy {policy['policyid']} uses a general service ({policy['service'][0]['name']})")
            selected_service = available_services[0]  # Automatically select first for web use
            policy['service'][0]['name'] = selected_service
            updated = True
        
        if updated:
            update_fortigate_config(f"{policies_endpoint}/{policy['policyid']}", policy)
            remediated_policies.append({
                'name': policy['name'],
                'id': policy['policyid']
            })
    return remediated_policies

# Other remediation functions: zones, interfaces, USB, TLS

def generate_remediation_report(remediated_policies, remediated_zones, remediated_interfaces, remediated_usb, remediated_tls):
    html_report = Template(html_template).render(
        remediated_policies=remediated_policies,
        remediated_zones=remediated_zones,
        remediated_interfaces=remediated_interfaces,
        remediated_usb=remediated_usb,
        remediated_tls=remediated_tls
    )

    with open("FortiGate_Remediation_Report.html", "w") as file:
        file.write(html_report)

    print("Remediation report generated: FortiGate_Remediation_Report.html")

# Main function to apply all remediations
def apply_all_remediations():
    print("Starting remediation process...")
    
    # Lists to store remediated items
    remediated_policies = remediate_policy()
    remediated_zones = []  # Call zone remediation here
    remediated_interfaces = []  # Call interface remediation here
    remediated_usb = False  # Call USB remediation here
    remediated_tls = False  # Call TLS remediation here

    # Generate the remediation report
    generate_remediation_report(remediated_policies, remediated_zones, remediated_interfaces, remediated_usb, remediated_tls)
    
    print("Remediation process completed.")

if __name__ == "__main__":
    apply_all_remediations()
