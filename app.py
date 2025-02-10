from flask import Flask, render_template, request, jsonify, redirect, url_for,send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from pymisp import PyMISP
import json
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO

app = Flask(__name__)
@app.route('/generate_pdf/<int:assessment_id>')
def generate_pdf(assessment_id):
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    
    # Create a buffer for the PDF
    buffer = BytesIO()
    
    # Create the PDF object
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph(f"Risk Assessment Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Define sections and their data
    sections = [
        ("System Characterization", [
            ("Asset Name", assessment.asset_name),
            ("Asset Type", assessment.asset_type),
            ("System Owner", assessment.system_owner),
            ("Data Classification", assessment.data_classification),
            ("Business Impact", assessment.business_impact)
        ]),
        ("Threat Identification", [
            ("Threat Source", assessment.threat_source),
            ("Threat Category", assessment.threat_category),
            ("Historical Occurrence", assessment.historical_occurrence),
            ("Threat Description", assessment.threat_description)
        ]),
        ("Vulnerability Assessment", [
            ("Known Vulnerability", assessment.known_vulnerability),
            ("Vulnerability Category", assessment.vulnerability_category),
            ("Exploitability Level", assessment.exploitability_level)
        ]),
        ("Control Analysis", [
            ("Existing Controls", assessment.existing_controls),
            ("Control Type", assessment.control_type)
        ]),
        ("Risk Assessment", [
            ("Likelihood Level", assessment.likelihood_level),
            ("Impact Level", assessment.impact_level),
            ("Residual Risk", assessment.residual_risk),
            ("Likelihood Justification", assessment.likelihood_justification),
            ("Impact Justification", assessment.impact_justification),
            ("Residual Risk Justification", assessment.residual_risk_justification),
            ("Control Recommendations", assessment.control_recommendations)
        ])
    ]
    
    # Add each section to the PDF
    for section_title, section_data in sections:
        elements.append(Paragraph(section_title, styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        # Create table for section data
        data = [[Paragraph(str(key), styles['Heading4']), 
                Paragraph(str(value), styles['Normal'])] 
                for key, value in section_data]
        
        table = Table(data, colWidths=[150, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))
    
    # Build PDF
    doc.build(elements)
    
    # Prepare response
    buffer.seek(0)
    return send_file(
        buffer,
        download_name=f'risk_assessment_{assessment_id}.pdf',
        as_attachment=True,
        mimetype='application/pdf'
    )

# Existing imports and configuration remain the same...

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_assessment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Add MISP configuration
app.config['MISP_URL'] = 'https://192.168.56.102'
app.config['MISP_KEY'] = '2reFFzBzZgD1dyXFGsjSZLHbHtCeUw7dmAfH9bwn'
app.config['MISP_VERIFY_CERT'] = False

# Initialize MISP
def init_misp():
    return PyMISP(
        app.config['MISP_URL'],
        app.config['MISP_KEY'],
        app.config['MISP_VERIFY_CERT']
    )

# Add new MISP-related routes and functions
@app.route('/misp/latest_threats')
def get_latest_threats():
    try:
        misp = init_misp()
        # Get events from the last 30 days
        events = misp.search(controller='events', last='30d')
        
        processed_events = []
        for event in events:
            if isinstance(event, dict) and 'Event' in event:
                event_data = event['Event']
                processed_events.append({
                    'id': event_data.get('id'),
                    'date': event_data.get('date'),
                    'threat_level': event_data.get('threat_level_id'),
                    'info': event_data.get('info'),
                    'analysis': event_data.get('analysis'),
                    'tags': [tag['Tag']['name'] for tag in event_data.get('Tag', [])]
                })
        
        return jsonify(processed_events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/misp/indicators/<event_id>')
def get_event_indicators(event_id):
    try:
        misp = init_misp()
        event = misp.get_event(event_id)
        
        indicators = []
        if event and 'Event' in event:
            for attribute in event['Event'].get('Attribute', []):
                indicators.append({
                    'type': attribute.get('type'),
                    'value': attribute.get('value'),
                    'category': attribute.get('category'),
                    'timestamp': attribute.get('timestamp')
                })
        
        return jsonify(indicators)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/misp/dashboard')
def misp_dashboard():
    return render_template('misp_dashboard.html')

# Add MISP correlation to risk assessments
@app.route('/correlate_threats/<int:assessment_id>')
def correlate_threats(assessment_id):
    try:
        assessment = RiskAssessment.query.get_or_404(assessment_id)
        misp = init_misp()
        
        # Search for related threats based on asset type and vulnerability category
        search_terms = f"{assessment.asset_type} {assessment.vulnerability_category}"
        related_events = misp.search(controller='events', value=search_terms)
        
        correlated_threats = []
        for event in related_events:
            if isinstance(event, dict) and 'Event' in event:
                event_data = event['Event']
                correlated_threats.append({
                    'id': event_data.get('id'),
                    'date': event_data.get('date'),
                    'info': event_data.get('info'),
                    'threat_level': event_data.get('threat_level_id')
                })
        
        return jsonify(correlated_threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


class RiskAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Step 1: System Characterization
    asset_name = db.Column(db.String(100))
    asset_type = db.Column(db.String(50))
    system_owner = db.Column(db.String(100))
    data_classification = db.Column(db.String(50))
    business_impact = db.Column(db.String(50))
    
    # Step 2: Threat Identification
    threat_source = db.Column(db.String(50))
    threat_category = db.Column(db.String(50))
    threat_description = db.Column(db.Text)
    historical_occurrence = db.Column(db.String(3))
    
    # Step 3: Vulnerability Identification
    known_vulnerability = db.Column(db.String(3))
    vulnerability_category = db.Column(db.String(50))
    exploitability_level = db.Column(db.String(50))
    
    # Step 4: Control Analysis
    existing_controls = db.Column(db.String(100))
    control_type = db.Column(db.String(50))
    
    # Step 5: Likelihood Estimation
    likelihood_level = db.Column(db.String(50))
    likelihood_justification = db.Column(db.Text)
    
    # Step 6: Impact Assessment
    impact_level = db.Column(db.String(50))
    impact_justification = db.Column(db.Text)
    
    # Step 7: Risk Calculation
    calculated_risk = db.Column(db.String(50))
    
    # Step 8: Residual Risk Assessment
    residual_risk = db.Column(db.String(50))
    residual_risk_justification = db.Column(db.Text)
    control_recommendations= db.Column(db.Text)
    
    # Additional fields
    status = db.Column(db.String(20), default='Active')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'asset_name': self.asset_name,
            'asset_type': self.asset_type,
            'system_owner': self.system_owner,
            'threat_level': self.likelihood_level,
            'impact_level': self.impact_level,
            'risk_level': self.residual_risk,
            'status': self.status,
            'date_created': self.date_created.isoformat(),
            'details': {
                'data_classification': self.data_classification,
                'business_impact': self.business_impact,
                'threat_source': self.threat_source,
                'threat_category': self.threat_category,
                'vulnerability_category': self.vulnerability_category,
                'existing_controls': self.existing_controls,
            }
        }

@app.route('/')
def index():
    return render_template('project.html')

@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/save_step', methods=['POST'])
def save_step():
    data = request.json
    step = data.get('step')
    assessment_id = data.get('assessment_id')
    
    if assessment_id:
        assessment = RiskAssessment.query.get(assessment_id)
    else:
        assessment = RiskAssessment()
    
    # Update fields based on step
    if step == 1:
        assessment.asset_name = data.get('asset_name')
        assessment.asset_type = data.get('asset_type')
        assessment.system_owner = data.get('system_owner')
        assessment.data_classification = data.get('data_classification')
        assessment.business_impact = data.get('business_impact')
    elif step == 2:
        assessment.threat_source = data.get('threat_source')
        assessment.threat_category = data.get('threat_category')
        assessment.threat_description = data.get('threat_description')
        assessment.historical_occurrence = data.get('historical_occurrence')
    elif step == 3:
        assessment.known_vulnerability = data.get('known_vulnerability')
        assessment.vulnerability_category = data.get('vulnerability_category')
        assessment.exploitability_level = data.get('exploitability_level')
    elif step == 4:
        assessment.existing_controls = data.get('existing_controls')
        assessment.control_type = data.get('control_type')
    elif step == 5:
        assessment.likelihood_level = data.get('likelihood_level')
        assessment.likelihood_justification = data.get('likelihood_justification')
    elif step == 6:
        assessment.impact_level = data.get('impact_level')
        assessment.impact_justification = data.get('impact_justification')
    elif step == 7:
        assessment.calculated_risk = data.get('calculated_risk')
    elif step == 8:
        assessment.residual_risk = data.get('residual_risk')
        assessment.residual_risk_justification = data.get('residual_risk_justification')
        assessment.control_recommendations = data.get('control_recommendations')
        
    
    db.session.add(assessment)
    db.session.commit()
    
    return jsonify({'success': True, 'assessment_id': assessment.id})

@app.route('/submit_assessment', methods=['POST'])
def submit_assessment():
    assessment_id = request.json.get('assessment_id')
    assessment = RiskAssessment.query.get(assessment_id)
    
    if not assessment:
        return jsonify({'success': False, 'error': 'Assessment not found'})
    
    assessment.status = 'Completed'
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/projects')
def projects():
    assessments = RiskAssessment.query.all()
    return render_template('project.html', projects=[a.to_dict() for a in assessments])

@app.route('/dashboard/<int:assessment_id>')
def dashboard(assessment_id):
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    return render_template('dashboard.html', assessment=assessment.to_dict())

@app.route('/assessment/<int:assessment_id>')
def get_assessment(assessment_id):
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    return jsonify(assessment.to_dict())

@app.route('/delete_assessment/<int:assessment_id>', methods=['POST','GET'])
def delete_assessment(assessment_id):
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    db.session.delete(assessment)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/view_assessments', methods=['GET'])
def view_assessments():
    assessments = RiskAssessment.query.all()
    return jsonify([assessment.to_dict() for assessment in assessments])

@app.route('/edit_assessment/<int:assessment_id>', methods=['GET', 'POST'])
def edit_assessment(assessment_id):
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    if request.method == 'POST':
        # Get JSON data from request
        data = request.get_json()
        
        # Update only the fields that are present in the request
        if 'asset_name' in data:
            assessment.asset_name = data['asset_name']
        if 'asset_type' in data:
            assessment.asset_type = data['asset_type']
        if 'system_owner' in data:
            assessment.system_owner = data['system_owner']
        if 'data_classification' in data:
            assessment.data_classification = data['data_classification']
        if 'business_impact' in data:
            assessment.business_impact = data['business_impact']
        if 'threat_source' in data:
            assessment.threat_source = data['threat_source']
        if 'threat_category' in data:
            assessment.threat_category = data['threat_category']
        if 'threat_description' in data:
            assessment.threat_description = data['threat_description']
        if 'historical_occurrence' in data:
            assessment.historical_occurrence = data['historical_occurrence']
        if 'known_vulnerability' in data:
            assessment.known_vulnerability = data['known_vulnerability']
        if 'vulnerability_category' in data:
            assessment.vulnerability_category = data['vulnerability_category']
        if 'exploitability_level' in data:
            assessment.exploitability_level = data['exploitability_level']
        if 'existing_controls' in data:
            assessment.existing_controls = data['existing_controls']
        if 'control_type' in data:
            assessment.control_type = data['control_type']
        if 'likelihood_level' in data:
            assessment.likelihood_level = data['likelihood_level']
        if 'likelihood_justification' in data:
            assessment.likelihood_justification = data['likelihood_justification']
        if 'impact_level' in data:
            assessment.impact_level = data['impact_level']
        if 'impact_justification' in data:
            assessment.impact_justification = data['impact_justification']
        if 'calculated_risk' in data:
            assessment.calculated_risk = data['calculated_risk']
        if 'residual_risk' in data:
            assessment.residual_risk = data['residual_risk']
        if 'residual_risk_justification' in data:
            assessment.residual_risk_justification = data['residual_risk_justification']
        if 'control_recommendations' in data:
            assessment.control_recommendations = data['control_recommendations']
        
        db.session.commit()
        return jsonify({'success': True})
    
    return render_template('edit_form.html', assessment=assessment)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
