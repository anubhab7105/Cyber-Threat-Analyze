from flask import Flask, render_template, request, jsonify
import scanner
import time
import re
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data['url'].strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        start_time = time.time()
        findings = scanner.scan_website(url)
        elapsed = time.time() - start_time
        
        # Calculate risk score (enhanced calculation)
        risk_score = min(100, calculate_risk_score(findings))
        is_risky = risk_score > 30
        
        # Generate threat verdict
        if risk_score > 80:
            verdict = "Critical Risk"
        elif risk_score > 60:
            verdict = "High Risk"
        elif risk_score > 40:
            verdict = "Medium Risk"
        elif risk_score > 20:
            verdict = "Low Risk"
        else:
            verdict = "Very Low Risk"
            
        # Generate analysis
        analysis = generate_analysis(findings, risk_score)
        
        # Make URLs clickable in findings
        processed_findings = []
        for finding in findings:
            # Extract URLs and make them clickable
            urls = re.findall(r'https?://[^\s]+', finding)
            for url in urls:
                finding = finding.replace(url, f'<a href="{url}" target="_blank">{url}</a>')
            processed_findings.append(finding)
        
        return jsonify({
            'is_risky': is_risky,
            'risk_score': risk_score,
            'verdict': verdict,
            'message': f"Found {len(findings)} security issues",
            'analysis': analysis,
            'technical_details': processed_findings,
            'scan_time': f"{elapsed:.2f} seconds"
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'is_risky': True,
            'risk_score': 100,
            'verdict': 'Scan Failed',
            'message': 'Error during scanning'
        }), 500

def calculate_risk_score(findings):
    """Calculate risk score based on findings severity"""
    score = 0
    critical_keywords = [
        'Exposed sensitive file', 
        'Domain breached', 
        'TRACE method enabled',
        'credentials'
    ]
    
    for finding in findings:
        # Critical findings
        if any(keyword in finding for keyword in critical_keywords):
            score += 20
        # High severity
        elif 'Directory listing' in finding:
            score += 15
        # Medium severity
        elif 'Missing' in finding or 'HTTPS' in finding:
            score += 10
        # Low severity
        else:
            score += 5
            
    return min(score, 100)

def generate_analysis(findings, risk_score):
    """Generate detailed threat assessment"""
    if not findings or "No critical" in findings[0]:
        return "Threat Assessment:\n✅ The target appears secure with no critical vulnerabilities detected.\n\nRecommendations:\n• Maintain regular security audits\n• Implement security headers for enhanced protection"

    # Categorize findings
    critical = []
    warnings = []
    recommendations = []
    
    for finding in findings:
        if 'Exposed sensitive file' in finding:
            critical.append(finding)
            recommendations.append("• Immediately remove or restrict access to exposed files")
        elif 'Domain breached' in finding:
            critical.append(finding)
            recommendations.append("• Reset all user credentials and enforce MFA")
            recommendations.append("• Monitor for suspicious activity")
        elif 'Directory listing' in finding:
            warnings.append(finding)
            recommendations.append("• Disable directory listing in server configuration")
        elif 'Missing' in finding:
            warnings.append(finding)
            recommendations.append("• Implement missing security headers")
        elif 'HTTPS' in finding:
            warnings.append(finding)
            recommendations.append("• Configure proper HTTPS redirection")
        elif 'TRACE method' in finding:
            critical.append(finding)
            recommendations.append("• Disable TRACE method on server")
        else:
            warnings.append(finding)

    # Build analysis report
    analysis = "Threat Assessment:\n"
    
    if critical:
        analysis += "\n🔴 Critical Issues Found:\n"
        analysis += "\n".join([f"• {item}" for item in critical]) + "\n"
    
    if warnings:
        analysis += "\n🟠 Security Warnings:\n"
        analysis += "\n".join([f"• {item}" for item in warnings]) + "\n"
    
    if recommendations:
        analysis += "\n🔧 Recommended Actions:\n"
        analysis += "\n".join(set(recommendations)) + "\n"
    
    # Add risk summary
    if risk_score > 80:
        analysis += "\n🚨 Critical Risk: Immediate action required to prevent data breaches"
    elif risk_score > 60:
        analysis += "\n⚠️ High Risk: Significant vulnerabilities require prompt attention"
    elif risk_score > 40:
        analysis += "\n⚠️ Medium Risk: Security improvements recommended"
    else:
        analysis += "\nℹ️ Low Risk: Maintain current security practices"
    
    # Add general recommendations
    analysis += "\n\n🔒 Security Best Practices:\n"
    analysis += "• Keep all software updated\n"
    analysis += "• Implement a Web Application Firewall\n"
    analysis += "• Conduct regular vulnerability scans\n"
    analysis += "• Use strong encryption protocols\n"
    
    return analysis

if __name__ == '__main__':
    app.run(debug=True)