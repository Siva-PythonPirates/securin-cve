from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import requests

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:admin@localhost/cve_database"
db = SQLAlchemy(app)

class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), unique=True)
    source_identifier = db.Column(db.String(100))
    published = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    vuln_status = db.Column(db.String(20))
    description = db.Column(db.Text())
    cvss_version = db.Column(db.String(10))
    cvss_vector = db.Column(db.String(50))
    access_vector = db.Column(db.String(20))
    access_complexity = db.Column(db.String(20))
    authentication = db.Column(db.String(20))
    confidentiality_impact = db.Column(db.String(20))
    integrity_impact = db.Column(db.String(20))
    availability_impact = db.Column(db.String(20))
    base_score = db.Column(db.Float)
    base_severity = db.Column(db.String(20))
    exploitability_score = db.Column(db.Float)
    impact_score = db.Column(db.Float)
    ac_insuf_info = db.Column(db.Boolean)
    obtain_all_privilege = db.Column(db.Boolean)
    obtain_user_privilege = db.Column(db.Boolean)
    obtain_other_privilege = db.Column(db.Boolean)
    user_interaction_required = db.Column(db.Boolean)
    cpe_records = db.relationship('CPE', backref='cve', lazy=True)

class CPE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), db.ForeignKey('cve.id'), nullable=False)
    criteria = db.Column(db.String(200))
    match_criteria_id = db.Column(db.String(50))
    vulnerable = db.Column(db.Boolean)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/cves/list", methods=["GET"])
def get_cves_list():
    # Get query parameters
    results_per_page = int(request.args.get("resultsPerPage", 10))
    page = int(request.args.get("page", 1))
    offset = (page - 1) * results_per_page

    # Query CVEs with pagination
    cves = CVE.query.offset(offset).limit(results_per_page).all()

    # Total number of records
    total_records = CVE.query.count()

    return jsonify({
        "cves": [{"id": cve.id, "cve_id": cve.cve_id, "source_identifier": cve.source_identifier,
                  "published": cve.published.strftime("%Y-%m-%d %H:%M:%S"),
                  "last_modified": cve.last_modified.strftime("%Y-%m-%d %H:%M:%S"),
                  "vuln_status": cve.vuln_status} for cve in cves],
        "totalRecords": total_records,
        "currentPage": page
    })

@app.route("/cves/<string:cve_id>", methods=["GET"])
def get_cve_details(cve_id):
    cve = CVE.query.filter_by(cve_id=cve_id).first()
    if cve:
        cpe_records = CPE.query.filter_by(cve_id=cve.cve_id).all()
        
        # Determine score color
        if cve.base_score <= 3.33:
            score_color = "green"
        elif cve.base_score <= 6.66:
            score_color = "orange"
        else:
            score_color = "red"
        
        return render_template("cve_details.html", cve=cve, cpe_records=cpe_records, score_color=score_color)
    return jsonify({"error": "CVE not found"}), 404
@app.route("/cves/sync", methods=["GET"])
def sync_cves():
    response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"startIndex": 0, "resultsPerPage": 2000})
    cves_data = response.json()["vulnerabilities"]
    
    for cve_data in cves_data:
        cve_id = cve_data["cve"]["id"]
        source_identifier = cve_data["cve"]["sourceIdentifier"]
        published = cve_data["cve"]["published"]
        last_modified = cve_data["cve"]["lastModified"] 
        vuln_status = cve_data["cve"]["vulnStatus"]
        description = cve_data["cve"]["descriptions"][0]["value"]
        
        # Check if 'cvssMetricV2' key exists
        cvss_data = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else {}
        cvss_version = cvss_data.get("version")
        cvss_vector = cvss_data.get("vectorString")
        access_vector = cvss_data.get("accessVector")
        access_complexity = cvss_data.get("accessComplexity")
        authentication = cvss_data.get("authentication")
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        base_score = cvss_data.get("baseScore")
        base_severity = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        exploitability_score = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        impact_score = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        ac_insuf_info = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["acInsufInfo"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        obtain_all_privilege = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["obtainAllPrivilege"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        obtain_user_privilege = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["obtainUserPrivilege"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        obtain_other_privilege = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["obtainOtherPrivilege"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None
        user_interaction_required = cve_data["cve"]["metrics"]["cvssMetricV2"][0]["userInteractionRequired"] if "cvssMetricV2" in cve_data["cve"]["metrics"] else None

        # Extract CPE details
        cpe_records = []
        if "configurations" in cve_data['cve']:
            for config in cve_data['cve']['configurations']:
                for node in config['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe_criteria = cpe_match['criteria']
                        match_criteria_id = cpe_match['matchCriteriaId']
                        vulnerable = cpe_match['vulnerable']
                        cpe_records.append(CPE(cve_id=cve_id, criteria=cpe_criteria, match_criteria_id=match_criteria_id, vulnerable=vulnerable))

        # Check if CVE already exists
        existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
        if existing_cve:
            # Update existing CVE record
            existing_cve.source_identifier = source_identifier
            existing_cve.published = published
            existing_cve.last_modified = last_modified
            existing_cve.vuln_status = vuln_status
            existing_cve.description = description
            existing_cve.cvss_version = cvss_version
            existing_cve.cvss_vector = cvss_vector
            existing_cve.access_vector = access_vector
            existing_cve.access_complexity = access_complexity
            existing_cve.authentication = authentication
            existing_cve.confidentiality_impact = confidentiality_impact
            existing_cve.integrity_impact = integrity_impact
            existing_cve.availability_impact = availability_impact
            existing_cve.base_score = base_score
            existing_cve.base_severity = base_severity
            existing_cve.exploitability_score = exploitability_score
            existing_cve.impact_score = impact_score
            existing_cve.ac_insuf_info = ac_insuf_info
            existing_cve.obtain_all_privilege = obtain_all_privilege
            existing_cve.obtain_user_privilege = obtain_user_privilege
            existing_cve.obtain_other_privilege = obtain_other_privilege
            existing_cve.user_interaction_required = user_interaction_required
        else:
            # Create new CVE record
            new_cve = CVE(cve_id=cve_id, source_identifier=source_identifier, published=published,
                          last_modified=last_modified, vuln_status=vuln_status, description=description,
                          cvss_version=cvss_version, cvss_vector=cvss_vector, access_vector=access_vector,
                          access_complexity=access_complexity, authentication=authentication,
                          confidentiality_impact=confidentiality_impact, integrity_impact=integrity_impact,
                          availability_impact=availability_impact, base_score=base_score, base_severity=base_severity,
                          exploitability_score=exploitability_score, impact_score=impact_score,
                          ac_insuf_info=ac_insuf_info, obtain_all_privilege=obtain_all_privilege,
                          obtain_user_privilege=obtain_user_privilege, obtain_other_privilege=obtain_other_privilege,
                          user_interaction_required=user_interaction_required)
            db.session.add(new_cve)

        # Commit changes to database
        db.session.commit()

        # Add CPE records to database
        db.session.add_all(cpe_records)
        db.session.commit()

    return "CVEs synced successfully!"

if __name__ == "__main__":
    app.run(debug=True)
