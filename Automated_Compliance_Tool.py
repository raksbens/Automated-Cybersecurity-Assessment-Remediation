from flask import Flask, render_template, request, redirect, url_for, flash, session
import subprocess
import requests
from jinja2 import Template
from Final_Firewall_remediation import fetch_ip_addresses, fetch_services, update_fortigate_config, fetch_policies

app = Flask(__name__)
app.secret_key = '<Enter Flask secret key>'

# FortiGate API details
BASE_URL = "https://<Fortigate_firewall_ip_address>/api/v2/cmdb"
HEADERS = {'Authorization': 'Bearer <api_key>'}

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
    {% if remediated_policy %}
        <h3>Remediated Policy</h3>
        <ul>
            <li class="remediated">Policy ID: {{ remediated_policy }}</li>
        </ul>
    {% endif %}

    {% if not remediated_policy %}
        <p class="no-remediation">No controls were remediated.</p>
    {% endif %}
</body>
</html>
"""

# Route to render the index page
@app.route('/')
def index():
    return render_template('index.html')

# Route to trigger FortiGate Firewall Assessment
@app.route('/run_fortigate_assessment')
def run_fortigate_assessment():
    try:
        result = subprocess.run(['python', 'Final_Firewall_03092024_01.py'], capture_output=True, text=True)
        flash(f"FortiGate Firewall Assessment Completed. Output:\n{result.stdout}", 'success')
    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
    return redirect(url_for('index'))

# Route to handle the FortiGate Remediation process
@app.route('/run_fortigate_remediation')
def run_fortigate_remediation():
    # Fetch IP addresses, services, and policies from FortiGate for user selection
    ip_addresses = fetch_ip_addresses()
    services = fetch_services()
    policies = fetch_policies()

    if not ip_addresses or not services or not policies:
        flash("Error fetching IP addresses, services, or policies from the FortiGate.", 'danger')
        return redirect(url_for('index'))
    
    # Store IP addresses, services, and policies in session for later use in remediation
    session['ip_addresses'] = ip_addresses
    session['services'] = services
    session['policies'] = policies

    # Redirect to the first remediation step: selecting the policy
    return redirect(url_for('remediation_select_policy'))

# Step 1: Select Policy
@app.route('/remediation_select_policy', methods=['GET', 'POST'])
def remediation_select_policy():
    if request.method == 'POST':
        session['selected_policy_id'] = request.form['policy_id']
        return redirect(url_for('remediation_select_src_addr'))  # Next step: select source address
    
    # Fetch policies stored in the session
    policies = session.get('policies', [])
    
    # Ensure policies are present
    if not policies:
        flash("No policies available for selection.", 'danger')
        return redirect(url_for('index'))

    return render_template('select_policy.html', policies=policies)

# Step 2: Select Source Address
@app.route('/remediation_select_src_addr', methods=['GET', 'POST'])
def remediation_select_src_addr():
    if request.method == 'POST':
        session['selected_src_addr'] = request.form['src_addr']
        return redirect(url_for('remediation_select_dst_addr'))  # Next step: select destination address
    
    # Fetch IP addresses stored in the session
    ip_addresses = session.get('ip_addresses', [])
    
    # Ensure IP addresses are present
    if not ip_addresses:
        flash("No IP addresses available for source selection.", 'danger')
        return redirect(url_for('index'))

    return render_template('select_src_addr.html', ip_addresses=ip_addresses)

# Step 3: Select Destination Address
@app.route('/remediation_select_dst_addr', methods=['GET', 'POST'])
def remediation_select_dst_addr():
    if request.method == 'POST':
        session['selected_dst_addr'] = request.form['dst_addr']
        return redirect(url_for('remediation_select_service'))
    
    # Fetch IP addresses stored in the session
    ip_addresses = session.get('ip_addresses', [])
    
    # Ensure IP addresses are present
    if not ip_addresses:
        flash("No IP addresses available for destination selection.", 'danger')
        return redirect(url_for('index'))

    return render_template('select_dst_addr.html', ip_addresses=ip_addresses)

# Step 4: Select Service
@app.route('/remediation_select_service', methods=['GET', 'POST'])
def remediation_select_service():
    if request.method == 'POST':
        session['selected_service'] = request.form['service']
        return redirect(url_for('apply_remediation'))  # Final step: apply remediation
    
    # Fetch services stored in the session
    services = session.get('services', [])
    
    # Ensure services are present
    if not services:
        flash("No services available for selection.", 'danger')
        return redirect(url_for('index'))

    return render_template('select_service.html', services=services)

# Final Step: Apply the remediation and generate the report
@app.route('/apply_remediation', methods=['GET', 'POST'])
def apply_remediation():
    try:
        # Retrieve selected values from the session
        selected_policy_id = session.get('selected_policy_id')
        selected_src = session.get('selected_src_addr')
        selected_dst = session.get('selected_dst_addr')
        selected_service = session.get('selected_service')
        
        # Ensure all values are present
        if not selected_policy_id or not selected_src or not selected_dst or not selected_service:
            flash("Some information is missing. Please restart the remediation process.", 'danger')
            return redirect(url_for('index'))

        # Apply remediation by sending a PUT request to update the policy
        policy = {
            'srcaddr': [{'name': selected_src}],
            'dstaddr': [{'name': selected_dst}],
            'service': [{'name': selected_service}]
        }
        
        # Use the selected policy ID
        update_fortigate_config(f'/firewall/policy/{selected_policy_id}', policy)

        # Generate the remediation report
        generate_remediation_report(selected_policy_id)
        flash("FortiGate Firewall Remediation Completed. Report generated.", 'success')

    except Exception as e:
        flash(f"Error during remediation: {str(e)}", 'danger')

    return redirect(url_for('index'))

# Function to generate the remediation report
def generate_remediation_report(remediated_policy):
    # Render the HTML report using Jinja2
    html_report = Template(html_template).render(
        remediated_policy=remediated_policy
    )

    # Write the HTML report to a file
    with open("FortiGate_Remediation_Report.html", "w") as file:
        file.write(html_report)

    print("Remediation report generated: FortiGate_Remediation_Report.html")

# Route to trigger Ubuntu OS Assessment
@app.route('/run_ubuntu_assessment')
def run_ubuntu_assessment():
    try:
        result = subprocess.run(['python', 'E:\\Compliance Assessment Codes\\Ubuntu_Server_Compliance_Assessment.py'], capture_output=True, text=True)
        flash(f"Ubuntu OS Assessment Completed. Output:\n{result.stdout}", 'success')
    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
    return redirect(url_for('index'))

# Route to trigger Windows Host Assessment
@app.route('/run_windows_assessment')
def run_windows_assessment():
    try:
        script_path = 'E:\\Compliance Assessment Codes\\Windows_Host_Compliance_Assessment.py'
        result = subprocess.run(['python', script_path], capture_output=True, text=True)
        if result.stdout:
            flash(f"Windows Host Assessment Completed. Output:\n{result.stdout}", 'success')
        if result.stderr:
            flash(f"Error: {result.stderr}", 'danger')
        if not result.stdout and not result.stderr:
            flash("Windows Host Assessment completed but no output was produced.", 'warning')
    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
