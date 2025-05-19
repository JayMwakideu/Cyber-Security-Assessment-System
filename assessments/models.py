from django.db import models
from django.contrib.auth.models import User

class Organization(models.Model):
    name = models.CharField(max_length=255)
    mission = models.TextField(blank=True)
    employee_count = models.CharField(
        max_length=50,
        choices=[
            ('1-50', '1-50'),
            ('51-200', '51-200'),
            ('201-500', '201-500'),
            ('501-1000', '501-1000'),
            ('1000+', '1000+')
        ]
    )
    industry = models.CharField(
        max_length=50,
        choices=[
            ('Technology', 'Technology'),
            ('Finance', 'Finance'),
            ('Healthcare', 'Healthcare'),
            ('Education', 'Education'),
            ('Retail', 'Retail'),
            ('Other', 'Other')
        ]
    )
    compliance_requirements = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return self.name

class AssessmentBase(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    contact_person = models.CharField(max_length=100)
    contact_email = models.EmailField()
    contact_phone = models.CharField(max_length=20)
    date_completed = models.DateField()
    assessor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        abstract = True

class AssetInventory(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    workstations = models.IntegerField(default=0)
    laptops = models.IntegerField(default=0)
    mobile_devices = models.IntegerField(default=0)
    physical_servers = models.IntegerField(default=0)
    virtual_servers = models.IntegerField(default=0)
    cloud_services = models.TextField(blank=True)
    core_systems = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

class SecurityTool(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    tool_type = models.CharField(
        max_length=50,
        choices=[
            ('Antivirus', 'Antivirus'),
            ('Firewall', 'Firewall'),
            ('Email Security', 'Email Security'),
            ('Backup', 'Backup'),
            ('SIEM', 'SIEM'),
            ('Patch Management', 'Patch Management'),
            ('Endpoint Protection', 'Endpoint Protection')
        ]
    )
    tool_name = models.CharField(max_length=100)
    in_use = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

class MobileWebAssessment(AssessmentBase):
    app_name = models.CharField(max_length=255)
    platform = models.CharField(
        max_length=50,
        choices=[('iOS', 'iOS'), ('Android', 'Android'), ('Both', 'Both'), ('Web', 'Web')]
    )
    user_count = models.IntegerField()
    source_code_available = models.BooleanField()
    encryption_used = models.BooleanField()
    third_party_libraries = models.TextField(blank=True)
    data_sensitivity = models.CharField(
        max_length=50,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')]
    )
    vulnerabilities = models.TextField(blank=True)
    compliance_status = models.CharField(
        max_length=50,
        choices=[('Compliant', 'Compliant'), ('Non-Compliant', 'Non-Compliant'), ('Partial', 'Partial')]
    )
    ssl_tls_implemented = models.BooleanField(default=False)
    cms_used = models.TextField(blank=True)

class APIAssessment(AssessmentBase):
    api_name = models.CharField(max_length=255)
    endpoint_count = models.IntegerField()
    authentication_mechanism = models.CharField(max_length=100)
    data_sensitivity = models.CharField(
        max_length=50,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')]
    )
    is_internal = models.BooleanField(default=True)
    documentation_available = models.BooleanField()
    rate_limiting = models.BooleanField()
    vulnerabilities = models.TextField(blank=True)
    compliance_status = models.CharField(
        max_length=50,
        choices=[('Compliant', 'Compliant'), ('Non-Compliant', 'Non-Compliant'), ('Partial', 'Partial')]
    )
    third_party_integrations = models.TextField(blank=True)

class FirewallAssessment(AssessmentBase):
    firewall_type = models.CharField(max_length=100)
    rule_count = models.IntegerField()
    last_review_date = models.DateField()
    logging_enabled = models.BooleanField()
    vulnerabilities = models.TextField(blank=True)
    compliance_status = models.CharField(
        max_length=50,
        choices=[('Compliant', 'Compliant'), ('Non-Compliant', 'Non-Compliant'), ('Partial', 'Partial')]
    )
    redundant_rules = models.TextField(blank=True)
    shadowed_rules = models.TextField(blank=True)

class PhishingAssessment(AssessmentBase):
    staff_count = models.IntegerField()
    simulation_count = models.IntegerField()
    click_rate = models.FloatField()
    awareness_level = models.CharField(
        max_length=50,
        choices=[('High', 'High'), ('Moderate', 'Moderate'), ('Low', 'Low')]
    )
    feedback_provided = models.BooleanField()
    reported_phishing = models.FloatField()
    vulnerabilities = models.TextField(blank=True)

class MaturityAssessment(AssessmentBase):
    maturity_level = models.CharField(
        max_length=50,
        choices=[
            ('Non-existent', 'Non-existent'),
            ('Compliance Focused', 'Compliance Focused'),
            ('Behaviour Change', 'Behaviour Change'),
            ('Culture Change', 'Culture Change'),
            ('Optimization', 'Optimization')
        ]
    )
    training_frequency = models.CharField(
        max_length=50,
        choices=[
            ('Never', 'Never'),
            ('Yearly', 'Yearly'),
            ('Quarterly', 'Quarterly'),
            ('Monthly', 'Monthly'),
            ('Continuous', 'Continuous')
        ]
    )
    metrics_tracked = models.BooleanField()
    leadership_support = models.BooleanField()
    comments = models.TextField(blank=True)

class NISTAssessment(AssessmentBase):
    control_id = models.CharField(max_length=50)
    control_description = models.TextField()
    compliance_status = models.CharField(
        max_length=50,
        choices=[('Compliant', 'Compliant'), ('Non-Compliant', 'Non-Compliant'), ('Partial', 'Partial')]
    )
    gaps_identified = models.TextField(blank=True)
    control_family = models.CharField(max_length=100)

class AccessControl(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    privileged_users = models.IntegerField()
    mfa_implemented = models.BooleanField()
    strong_password_policy = models.BooleanField()
    role_based_access = models.BooleanField()
    onboarding_process = models.TextField(blank=True)
    offboarding_process = models.TextField(blank=True)
    notes = models.TextField(blank=True)

class NetworkSecurity(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    vlan_count = models.IntegerField()
    firewall_count = models.IntegerField()
    firewall_review_periodic = models.BooleanField()
    internal_ip_count = models.CharField(
        max_length=50,
        choices=[('<50', '<50'), ('50-200', '50-200'), ('201-500', '201-500'), ('501+', '501+')]
    )
    dns_provider = models.CharField(max_length=100)
    dns_monitoring = models.BooleanField()
    notes = models.TextField(blank=True)

class IncidentResponse(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    has_plan = models.BooleanField()
    last_test_date = models.DateField(null=True, blank=True)
    dedicated_team = models.BooleanField()
    cyber_insurance = models.BooleanField()
    top_threats = models.TextField(blank=True)
    business_impact = models.CharField(
        max_length=50,
        choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')]
    )
    budget = models.CharField(max_length=100, blank=True)
    challenges = models.TextField(blank=True)

class MaturityAnalysisHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    responses = models.JSONField()
    average_score = models.FloatField()
    maturity_percentage = models.FloatField()
    maturity_level = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)