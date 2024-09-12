import requests
from jinja2 import Template

# Constants
BASE_URL = "https://<Fortigate_firewall_ip_address>/api/v2/cmdb"
HEADERS = {'Authorization': 'Bearer <api_key>'}
CERT_PATH = r"C:\path\to\certificate.pem"  # Update with the correct path to your certificate

# HTML Template
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fortigate CIS Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
        h1 { color: #333; }
        h2 { color: #555; }
        .non-compliant { color: red; }
        .compliant { color: green; }
        .summary { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }
        .remediation { margin-top: 10px; padding: 10px; border: 1px solid #ddd; background-color: #f8f8f8; }
    </style>
</head>
<body>
    <h1>Fortigate CIS Compliance Report</h1>
    <h2>Summary</h2>
    <div class="summary">
        <p>Total Non-Compliant Policies: {{ non_compliant_policies }}</p>
        <p>Total Non-Compliant Zones: {{ non_compliant_zones }}</p>
        <p>Total Non-Compliant Interfaces: {{ non_compliant_interfaces }}</p>
        <p>Total Non-Compliant USB Settings: {{ non_compliant_usb }}</p>
        <p>Total Non-Compliant TLS Settings: {{ non_compliant_tls }}</p>
        <h3>Total Non-Compliance Count: {{ total_non_compliance }}</h3>
    </div>

    <h2>Detailed Report</h2>
    
    <h3>Policies</h3>
    {% for policy in policies %}
        <div>
            <h4>{{ policy.name }} (ID: {{ policy.id }})</h4>
            {% if policy.non_compliant %}
                <ul>
                    {% for issue in policy.issues %}
                    <li class="non-compliant">{{ issue }}</li>
                    {% endfor %}
                </ul>
                <div class="remediation">
                    <p><strong>Remediation:</strong></p>
                    <p>CIS Control v7 9.2 Ensure Only Approved Ports, Protocols and Services Are Running.</p>
                    <p>Ensure that only network ports, protocols, and services listening on a system with validated business needs are running on each system.</p>
                    <p>In GUI, Login to firewall, Go to Policies, select the Non-compliant policy and edit the IP address or services to select the specific ones.</p>
                </div>
            {% else %}
                <p class="compliant">Compliant</p>
            {% endif %}
        </div>
    {% endfor %}

    <h3>Zones</h3>
    {% for zone in zones %}
        <div>
            <h4>{{ zone.name }}</h4>
            {% if zone.non_compliant %}
                <p class="non-compliant">{{ zone.issue }}</p>
                <div class="remediation">
                    <p><strong>Remediation:</strong></p>
                    <p>CIS Control v7 2.10 Physically or Logically Segregate High Risk Applications.</p>
                    <p>Physically or logically segregated systems should be used to isolate and run software that is required for business operations but incurs higher risk for the organization.</p>
                    <p>In the GUI, click on Network -> Interfaces, select the zone and click on Edit and turn on Block intra-zone traffic.</p>
                </div>
            {% else %}
                <p class="compliant">Compliant</p>
            {% endif %}
        </div>
    {% endfor %}

    <h3>Interfaces</h3>
    {% for interface in interfaces %}
        <div>
            <h4>{{ interface.name }} (Role: {{ interface.role }})</h4>
            {% if interface.non_compliant %}
                <p class="non-compliant">{{ interface.issue }}</p>
                <div class="remediation">
                    <p><strong>Remediation:</strong></p>
                    <p>Go to Network > Interfaces. Review WAN interface and disable HTTPS, HTTP, ping, SSH, SNMP, and Radius services.</p>
                </div>
            {% else %}
                <p class="compliant">Compliant</p>
            {% endif %}
        </div>
    {% endfor %}

    <h3>USB Settings</h3>
    {% if usb.non_compliant %}
        <p class="non-compliant">{{ usb.issue }}</p>
        <div class="remediation">
            <p><strong>Remediation:</strong></p>
            <p>CLI:</p>
            <p>config system auto-install</p>
            <p>set auto-install-config disable</p>
            <p>set auto-install-image disable</p>
            <p>end</p>
        </div>
    {% else %}
        <p class="compliant">Compliant</p>
    {% endif %}

    <h3>TLS Settings</h3>
    {% if tls.non_compliant %}
        <p class="non-compliant">{{ tls.issue }}</p>
        <div class="remediation">
            <p><strong>Remediation:</strong></p>
            <p>CLI:</p>
            <p>config system global</p>
            <p>set ssl-static-key-ciphers disable</p>
            <p>end</p>
        </div>
    {% else %}
        <p class="compliant">Compliant</p>
    {% endif %}
</body>
</html>
"""

# Helper Functions
def get_data(endpoint):
    try:
        response = requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS, verify=False)
        response.raise_for_status()
        return response.json()['results']
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving data from {endpoint}: {e}")
        return []

def check_policy_compliance(policies):
    non_compliant_policies = []
    for policy in policies:
        issues = []
        recommendation = ""
        if policy['srcaddr'][0]['name'] == 'all':
            issues.append("Source address is 'all'. Please specify a specific IP address or range.")
            recommendation = "Change the source address to a specific IP or range to comply with security best practices."
        if policy['dstaddr'][0]['name'] == 'all':
            issues.append("Destination address is 'all'. Please specify a specific IP address or range.")
            recommendation = "Change the destination address to a specific IP or range to comply with security best practices."
        if policy['service'][0]['name'] in ['ALL', 'ALL_TCP', 'ALL_ICMP', 'ALL_UDP', 'ALL_ICMP6']:
            issues.append(f"Service is '{policy['service'][0]['name']}'. Please specify a specific service port.")
            recommendation = "Specify the exact service port instead of using 'ALL' to reduce the risk of unauthorized access."
        
        non_compliant_policies.append({
            'name': policy['name'],
            'id': policy['policyid'],
            'non_compliant': bool(issues),
            'issues': issues,
            'recommendation': recommendation
        })
    
    return non_compliant_policies

def check_zone_compliance(zones):
    non_compliant_zones = []
    for zone in zones:
        issue = None
        recommendation = None
        if zone['intrazone'] == 'allow':
            issue = f"Intra-zone traffic is allowed in zone '{zone['name']}'. It should be blocked."
            recommendation = "Change intra-zone traffic settings to 'deny' to prevent unauthorized access between zones."
        
        non_compliant_zones.append({
            'name': zone['name'],
            'non_compliant': bool(issue),
            'issue': issue,
            'recommendation': recommendation
        })
    
    return non_compliant_zones

def check_interface_compliance(interfaces):
    non_compliant_interfaces = []
    for interface in interfaces:
        issue = None
        recommendation = None
        if interface['role'] == 'wan' and any(service in interface.get('allowaccess', []) for service in ['ping', 'http', 'https', 'ssh', 'snmp', 'fgfm', 'radius-acct']):
            issue = f"WAN interface '{interface['name']}' has management services enabled."
            recommendation = "Disable management services on WAN interfaces to enhance security."
        
        non_compliant_interfaces.append({
            'name': interface['name'],
            'role': interface['role'],
            'non_compliant': bool(issue),
            'issue': issue,
            'recommendation': recommendation
        })
    
    return non_compliant_interfaces

def check_usb_installation(usb_settings):
    issue = None
    recommendation = None
    if usb_settings['auto-install-config'] == 'enable' or usb_settings['auto-install-image'] == 'enable':
        issue = "USB auto-install feature is enabled. It should be disabled."
        recommendation = "Disable USB auto-install feature to prevent potential security risks from unauthorized USB devices."

    return {
        'non_compliant': bool(issue),
        'issue': issue,
        'recommendation': recommendation
    }

def check_tls_compliance(global_settings):
    issue = None
    recommendation = None
    if global_settings['ssl-static-key-ciphers'] == 'enable':
        issue = "Static keys for TLS are enabled. They should be disabled."
        recommendation = "Disable static keys for TLS to enhance security and use dynamic key exchanges instead."

    return {
        'non_compliant': bool(issue),
        'issue': issue,
        'recommendation': recommendation
    }

# Main Script Execution
policies = check_policy_compliance(get_data("/firewall/policy"))
zones = check_zone_compliance(get_data("/system/zone"))
interfaces = check_interface_compliance(get_data("/system/interface"))
usb = check_usb_installation(get_data("/system/auto-install"))  # Assuming there's only one setting
tls = check_tls_compliance(get_data("/system/global"))  # Assuming there's only one global setting

# Summary of Non-Compliances
total_non_compliance = (len([p for p in policies if p['non_compliant']]) +
                        len([z for z in zones if z['non_compliant']]) +
                        len([i for i in interfaces if i['non_compliant']]) +
                        usb['non_compliant'] +
                        tls['non_compliant'])

# Render HTML
html_report = Template(html_template).render(
    policies=policies,
    zones=zones,
    interfaces=interfaces,
    usb=usb,
    tls=tls,
    non_compliant_policies=len([p for p in policies if p['non_compliant']]),
    non_compliant_zones=len([z for z in zones if z['non_compliant']]),
    non_compliant_interfaces=len([i for i in interfaces if i['non_compliant']]),
    non_compliant_usb=usb['non_compliant'],
    non_compliant_tls=tls['non_compliant'],
    total_non_compliance=total_non_compliance
)

# Write to HTML file
with open("CIS_Fortigate_Compliance_Report.html", "w") as file:
    file.write(html_report)

print("Report generated: CIS_Fortigate_Compliance_Report.html")
