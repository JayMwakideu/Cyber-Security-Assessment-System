from django import forms
from .models import (
    MobileWebAssessment, APIAssessment, FirewallAssessment,
    PhishingAssessment, MaturityAssessment, NISTAssessment,
    Organization, AssetInventory, AccessControl, NetworkSecurity,
    IncidentResponse
)

class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ['name', 'mission', 'employee_count', 'industry', 'compliance_requirements']
        widgets = {
            'mission': forms.Textarea(attrs={'rows': 4}),
            'compliance_requirements': forms.Textarea(attrs={'rows': 4}),
        }

class MobileWebForm(forms.ModelForm):
    class Meta:
        model = MobileWebAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'vulnerabilities': forms.Textarea(attrs={'rows': 4}),
            'third_party_libraries': forms.Textarea(attrs={'rows': 4}),
            'cms_used': forms.Textarea(attrs={'rows': 4}),
        }

class APIForm(forms.ModelForm):
    class Meta:
        model = APIAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'vulnerabilities': forms.Textarea(attrs={'rows': 4}),
            'third_party_integrations': forms.Textarea(attrs={'rows': 4}),
        }

class FirewallForm(forms.ModelForm):
    class Meta:
        model = FirewallAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'last_review_date': forms.DateInput(attrs={'type': 'date'}),
            'vulnerabilities': forms.Textarea(attrs={'rows': 4}),
            'redundant_rules': forms.Textarea(attrs={'rows': 4}),
            'shadowed_rules': forms.Textarea(attrs={'rows': 4}),
        }

class PhishingForm(forms.ModelForm):
    class Meta:
        model = PhishingAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'vulnerabilities': forms.Textarea(attrs={'rows': 4}),
        }

class MaturityForm(forms.ModelForm):
    class Meta:
        model = MaturityAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'comments': forms.Textarea(attrs={'rows': 4}),
        }

class NISTForm(forms.ModelForm):
    class Meta:
        model = NISTAssessment
        fields = '__all__'
        widgets = {
            'date_completed': forms.DateInput(attrs={'type': 'date'}),
            'control_description': forms.Textarea(attrs={'rows': 4}),
            'gaps_identified': forms.Textarea(attrs={'rows': 4}),
        }

class AssetInventoryForm(forms.ModelForm):
    class Meta:
        model = AssetInventory
        fields = '__all__'
        widgets = {
            'core_systems': forms.Textarea(attrs={'rows': 4}),
            'cloud_services': forms.Textarea(attrs={'rows': 4}),
            'notes': forms.Textarea(attrs={'rows': 4}),
        }

class AccessControlForm(forms.ModelForm):
    class Meta:
        model = AccessControl
        fields = '__all__'
        widgets = {
            'onboarding_process': forms.Textarea(attrs={'rows': 4}),
            'offboarding_process': forms.Textarea(attrs={'rows': 4}),
            'notes': forms.Textarea(attrs={'rows': 4}),
        }

class NetworkSecurityForm(forms.ModelForm):
    class Meta:
        model = NetworkSecurity
        fields = '__all__'
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 4}),
        }

class IncidentResponseForm(forms.ModelForm):
    class Meta:
        model = IncidentResponse
        fields = '__all__'
        widgets = {
            'last_test_date': forms.DateInput(attrs={'type': 'date'}),
            'top_threats': forms.Textarea(attrs={'rows': 4}),
            'challenges': forms.Textarea(attrs={'rows': 4}),
        }

class MaturityAnalysisForm(forms.Form):
    QUESTIONS = [
        "How are Data Governance Policies implemented?",
        "Ensuring data accuracy through standard practices?",
        "Encryption for sensitive data?",
        "Multi-factor authentication for critical systems?",
        "Enforcing data governance policies?",
        "Data Governance reporting structure?",
        "Classifying the Data Governance Team?",
        "Current data management lifecycle practices?",
        "Data security level?",
        "Leveraging AI and Data Analytics?"
    ]
    
    organization = forms.ModelChoiceField(queryset=Organization.objects.all(), label="Organization")
    
    for idx, question in enumerate(QUESTIONS):
        locals()[f'q{idx}_response'] = forms.ChoiceField(
            label=question,
            choices=[(i, str(i)) for i in range(6)],
            widget=forms.RadioSelect,
            initial=0
        )
        locals()[f'q{idx}_weight'] = forms.FloatField(
            label=f"Weight for {question}",
            initial=1.0,
            min_value=0.0,
            widget=forms.NumberInput(attrs={'step': '0.1'})
        )