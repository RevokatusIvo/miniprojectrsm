from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_assessment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
