import paramiko
from jinja2 import Template

# Constants
REMOTE_HOST = "<Ubuntu Server IP Address>"  # IP address of the Ubuntu server
USERNAME = "<Ubuntu Server Username>"  # Replace with your Ubuntu username
PASSWORD = "<Ubuntu Server Password>"  # Replace with your password

# HTML Template
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubuntu CIS Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
        h1 { color: #333; }
        h2 { color: #555; }
        .non-compliant { color: red; }
        .compliant { color: green; }
        .summary { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }
        .recommendation { font-style: italic; }
    </style>
</head>
<body>
    <h1>Ubuntu CIS Compliance Report</h1>
    <h2>Summary</h2>
    <div class="summary">
        <p>Total Non-Compliant Checks: {{ total_non_compliance }}</p>
    </div>

    <h2>Detailed Report</h2>

    <h3>Account Password Policy</h3>
    <p class="{{ 'non-compliant' if password_policy_non_compliant else 'compliant' }}">{{ password_policy }}</p>
    {% if password_policy_non_compliant %}
        <p class="recommendation">Recommendation: Set the minimum password length to 14 or more characters.</p>
        <p class="recommendation">Remediation: Edit the /etc/login.defs file and set PASS_MIN_LEN to 14.</p>
    {% endif %}

    <h3>SSH Configuration</h3>
    <p class="{{ 'non-compliant' if ssh_config_non_compliant else 'compliant' }}">{{ ssh_config }}</p>
    {% if ssh_config_non_compliant %}
        <p class="recommendation">Recommendation: Disable root login and password authentication in the SSH configuration.</p>
        <p class="recommendation">Remediation: Edit /etc/ssh/sshd_config and set PermitRootLogin no and PasswordAuthentication no. Restart the SSH service.</p>
    {% endif %}

    <h3>Firewall Status</h3>
    <p class="{{ 'non-compliant' if firewall_non_compliant else 'compliant' }}">{{ firewall_status }}</p>
    {% if firewall_non_compliant %}
        <p class="recommendation">Recommendation: Ensure that the firewall is active to protect the server.</p>
        <p class="recommendation">Remediation: Run 'sudo ufw enable' to activate the firewall and configure it as needed.</p>
    {% endif %}

    <h3>Audit Logs</h3>
    <ul>
    {% for log in audit_logs %}
        <li class="{{ 'non-compliant' if log['non_compliant'] else 'compliant' }}">{{ log['description'] }}</li>
    {% endfor %}
    </ul>
    {% for log in audit_logs if log['non_compliant'] %}
        <p class="recommendation">Recommendation: Ensure that auditd service is running to monitor and log system activities.</p>
        <p class="recommendation">Remediation: Run 'sudo systemctl start auditd' and 'sudo systemctl enable auditd' to start and enable the auditd service.</p>
    {% endfor %}
</body>
</html>
"""

# Function to execute commands on the remote server via SSH
def run_command(ssh_client, command, use_sudo=False):
    try:
        if use_sudo:
            command = f"echo '{PASSWORD}' | sudo -S {command}"
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        if error:
            raise RuntimeError(f"Error executing command: {error}")
        return output
    except Exception as e:
        return f"An error occurred: {e}"

# Connect to the remote Ubuntu server via SSH
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
    command = "cat /etc/login.defs | grep '^PASS_MIN_LEN'"
    output = run_command(ssh_client, command, use_sudo=True).strip()

    if output:
        if 'PASS_MIN_LEN' in output:
            parts = output.split()
            if len(parts) > 1 and parts[1].isdigit():
                min_length = parts[1]
                if int(min_length) >= 14:
                    return "Password minimum length is set to 14 or more (Compliant)", False
                else:
                    return "Password minimum length is less than 14 (Non-Compliant)", True
            else:
                return "PASS_MIN_LEN is present but does not have a valid value (Non-Compliant)", True
        else:
            return "PASS_MIN_LEN is present but not configured properly (Non-Compliant)", True
    else:
        return "PASS_MIN_LEN is not configured in /etc/login.defs (Non-Compliant)", True

# Check SSH configuration
def check_ssh_configuration(ssh_client):
    command = "cat /etc/ssh/sshd_config | grep '^PermitRootLogin'"
    output = run_command(ssh_client, command, use_sudo=True)
    if 'PermitRootLogin no' in output:
        return "Root login is disabled (Compliant)", False
    else:
        return "Root login is enabled (Non-Compliant)", True

# Check firewall status
def check_firewall_status(ssh_client):
    command = "ufw status"
    output = run_command(ssh_client, command, use_sudo=True)
    if 'Status: active' in output:
        return "Firewall is active (Compliant)", False
    else:
        return "Firewall is not active (Non-Compliant)", True

# Check audit logs
def check_audit_logs(ssh_client):
    logs = []

    # Example: Check if auditd service is running
    command = "systemctl status auditd | grep 'Active:'"
    output = run_command(ssh_client, command, use_sudo=True)
    if 'active (running)' in output:
        logs.append({"description": "auditd service is running (Compliant)", "non_compliant": False})
    else:
        logs.append({"description": "auditd service is not running (Non-Compliant)", "non_compliant": True})

    return logs

# Main Script Execution
try:
    ssh_client = connect_to_server(REMOTE_HOST, USERNAME, PASSWORD)

    # Collecting reports
    password_policy, password_policy_non_compliant = check_password_policy(ssh_client)
    ssh_config, ssh_config_non_compliant = check_ssh_configuration(ssh_client)
    firewall_status, firewall_non_compliant = check_firewall_status(ssh_client)
    audit_logs = check_audit_logs(ssh_client)

    # Close the SSH connection
    ssh_client.close()

    # Summary of Non-Compliances
    total_non_compliance = (len([log for log in audit_logs if log['non_compliant']]) +
                            (1 if password_policy_non_compliant else 0) +
                            (1 if ssh_config_non_compliant else 0) +
                            (1 if firewall_non_compliant else 0))

    # Render HTML
    html_report = Template(html_template).render(
        password_policy=password_policy,
        password_policy_non_compliant=password_policy_non_compliant,
        ssh_config=ssh_config,
        ssh_config_non_compliant=ssh_config_non_compliant,
        firewall_status=firewall_status,
        firewall_non_compliant=firewall_non_compliant,
        audit_logs=audit_logs,
        total_non_compliance=total_non_compliance
    )

    # Write to HTML file
    with open("Ubuntu_CIS_Compliance_Report.html", "w") as file:
        file.write(html_report)

    print("Report generated: Ubuntu_CIS_Compliance_Report.html")

except Exception as e:
    print(f"An error occurred: {e}")
