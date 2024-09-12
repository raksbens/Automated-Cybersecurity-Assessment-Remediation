import paramiko
from jinja2 import Template

# Constants
REMOTE_HOST = "<Windows Host IP Address>"  # IP address of the Windows machine
USERNAME = "<Windows Username>"  # Replace with your Windows username
PASSWORD = "<Windows Password>"  # Replace with your password (ensure to secure it properly)

# HTML Template
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows CIS Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
        h1 { color: #333; }
        h2 { color: #555; }
        .non-compliant { color: red; }
        .compliant { color: green; }
        .summary { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }
        .recommendation, .remediation { margin-top: 10px; padding: 10px; border: 1px solid #ddd; background-color: #f8f8f8; }
    </style>
</head>
<body>
    <h1>Windows CIS Compliance Report</h1>
    <h2>Summary</h2>
    <div class="summary">
        <p>Total Non-Compliant Checks: {{ total_non_compliance }}</p>
    </div>

    <h2>Detailed Report</h2>

    <h3>Password Policy</h3>
    <p class="{{ 'non-compliant' if password_policy_non_compliant else 'compliant' }}">{{ password_policy }}</p>
    {% if password_policy_non_compliant %}
        <div class="recommendation">
            <p><strong>Recommendation:</strong></p>
            <p>Ensure that the password policy meets organizational standards for minimum length and complexity.</p>
        </div>
        <div class="remediation">
            <p><strong>Remediation:</strong></p>
            <p>In GUI, go to Local Security Policy -> Account Policies -> Password Policy. Set the Minimum Password Length to 14 or more.</p>
        </div>
    {% endif %}

    <h3>Account Lockout Policy</h3>
    <p class="{{ 'non-compliant' if lockout_policy_non_compliant else 'compliant' }}">{{ lockout_policy }}</p>
    {% if lockout_policy_non_compliant %}
        <div class="recommendation">
            <p><strong>Recommendation:</strong></p>
            <p>Review and adjust account lockout policies to prevent unauthorized access attempts and ensure accounts are not left in a vulnerable state.</p>
        </div>
        <div class="remediation">
            <p><strong>Remediation:</strong></p>
            <p>In GUI, go to Local Security Policy -> Account Policies -> Account Lockout Policy. Configure the settings to ensure proper account lockout procedures are in place.</p>
        </div>
    {% endif %}

    <h3>Guest Account Status</h3>
    <p class="{{ 'non-compliant' if guest_account_non_compliant else 'compliant' }}">{{ guest_account_status }}</p>
    {% if guest_account_non_compliant %}
        <div class="recommendation">
            <p><strong>Recommendation:</strong></p>
            <p>Disable guest accounts to prevent unauthorized access and ensure compliance with security policies.</p>
        </div>
        <div class="remediation">
            <p><strong>Remediation:</strong></p>
            <p>In GUI, go to Local Users and Groups -> Users. Right-click on the Guest account and select Properties. Ensure the account is disabled.</p>
        </div>
    {% endif %}

    <h3>Audit Policy</h3>
    <ul>
    {% for audit in audit_policies %}
        <li class="{{ 'non-compliant' if audit.non_compliant else 'compliant' }}">
            {{ audit.description }}
            {% if audit.non_compliant %}
                <div class="recommendation">
                    <p><strong>Recommendation:</strong></p>
                    <p>Ensure audit policies are configured to log all relevant events for security monitoring and compliance purposes.</p>
                </div>
                <div class="remediation">
                    <p><strong>Remediation:</strong></p>
                    <p>In GUI, go to Local Security Policy -> Advanced Audit Policy Configuration. Enable the required audit policies for comprehensive logging.</p>
                </div>
            {% endif %}
        </li>
    {% endfor %}
    </ul>

    <h3>Service Configurations</h3>
    <ul>
    {% for service in services %}
        <li class="{{ 'non-compliant' if service.non_compliant else 'compliant' }}">
            {{ service.description }}
            {% if service.non_compliant %}
                <div class="recommendation">
                    <p><strong>Recommendation:</strong></p>
                    <p>Review service configurations and ensure all necessary services are running and non-essential services are disabled for improved security.</p>
                </div>
                <div class="remediation">
                    <p><strong>Remediation:</strong></p>
                    <p>In GUI, go to Services. Locate the non-compliant service and adjust its status to meet security requirements.</p>
                </div>
            {% endif %}
        </li>
    {% endfor %}
    </ul>
</body>
</html>
"""

# The rest of the code remains the same

# Function to execute PowerShell commands on the remote server via SSH
def run_powershell_command(ssh_client, command):
    try:
        command = f"powershell -Command \"{command}\""
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        if error:
            raise RuntimeError(f"Error executing command: {error}")
        return output
    except Exception as e:
        return f"An error occurred: {e}"

# Connect to the remote Windows server via SSH
def connect_to_server(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(hostname, username=username, password=password)
        print("Connected using password.")
        return ssh
    except Exception as e:
        print(f"Failed to connect: {e}")
        raise

# Check password policy
def check_password_policy(ssh_client):
    command = "Get-LocalUser | Select-Object Name,PasswordLastSet | Format-Table -AutoSize"
    minlen = run_powershell_command(ssh_client, command)
    if "MinimumPasswordLength 14" in minlen:
        return "Password minimum length is set to 14 or more (Compliant)", False
    else:
        return "Password minimum length is less than 14 (Non-Compliant)", True

# Check account lockout policy
def check_lockout_policy(ssh_client):
    command = "Get-LocalUser | Where-Object { $_.Name -eq 'Administrator' } | Select-Object -ExpandProperty AccountNeverExpires"
    account_lockout = run_powershell_command(ssh_client, command)
    if "True" in account_lockout:
        return "Account Lockout Policy is not properly configured (Non-Compliant)", True
    else:
        return "Account Lockout Policy is properly configured (Compliant)", False

# Check guest account status
def check_guest_account_status(ssh_client):
    command = "Get-LocalUser | Where-Object { $_.Name -eq 'Guest' } | Select-Object -ExpandProperty Enabled"
    guest_status = run_powershell_command(ssh_client, command)
    if "False" in guest_status:
        return "Guest account is disabled (Compliant)", False
    else:
        return "Guest account is enabled (Non-Compliant)", True

# Check audit policies
def check_audit_policies(ssh_client):
    audit_policies = []

    # Example: Check if Audit Logon Events are enabled
    command = "AuditPol /get /subcategory:'Logon'"
    audit_logon_events = run_powershell_command(ssh_client, command)
    if "Success and Failure" in audit_logon_events:
        audit_policies.append({"description": "Audit Logon Events are set to log both Success and Failure (Compliant)", "non_compliant": False})
    else:
        audit_policies.append({"description": "Audit Logon Events are not set to log both Success and Failure (Non-Compliant)", "non_compliant": True})

    return audit_policies

# Check service configurations
def check_services(ssh_client):
    services = []

    # Example: Check if Windows Firewall is active
    command = "Get-Service -Name MpsSvc | Select-Object Status"
    firewall_status = run_powershell_command(ssh_client, command)
    if "Running" in firewall_status:
        services.append({"description": "Windows Firewall is active (Compliant)", "non_compliant": False})
    else:
        services.append({"description": "Windows Firewall is not active (Non-Compliant)", "non_compliant": True})

    return services

# Main Script Execution
try:
    ssh_client = connect_to_server(REMOTE_HOST, USERNAME, PASSWORD)

    password_policy, password_policy_non_compliant = check_password_policy(ssh_client)
    lockout_policy, lockout_policy_non_compliant = check_lockout_policy(ssh_client)
    guest_account_status, guest_account_non_compliant = check_guest_account_status(ssh_client)
    audit_policies = check_audit_policies(ssh_client)
    services = check_services(ssh_client)

    # Close the SSH connection
    ssh_client.close()

    # Summary of Non-Compliances
    total_non_compliance = (len([a for a in audit_policies if a['non_compliant']]) + 
                            len([s for s in services if s['non_compliant']]) + 
                            (1 if password_policy_non_compliant else 0) +
                            (1 if lockout_policy_non_compliant else 0) +
                            (1 if guest_account_non_compliant else 0))

    # Render HTML
    html_report = Template(html_template).render(
        password_policy=password_policy,
        password_policy_non_compliant=password_policy_non_compliant,
        lockout_policy=lockout_policy,
        lockout_policy_non_compliant=lockout_policy_non_compliant,
        guest_account_status=guest_account_status,
        guest_account_non_compliant=guest_account_non_compliant,
        audit_policies=audit_policies,
        services=services,
        total_non_compliance=total_non_compliance
    )

    # Write to HTML file
    with open("Windows_CIS_Compliance_Report.html", "w") as file:
        file.write(html_report)

    print("Report generated: Windows_CIS_Compliance_Report.html")

except Exception as e:
    print(f"An error occurred: {e}")
