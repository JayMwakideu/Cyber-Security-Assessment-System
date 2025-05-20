
from .models import (
    MobileWebAssessment, APIAssessment, FirewallAssessment, PhishingAssessment,
    MaturityAssessment, NISTAssessment, Organization, AssetInventory, AccessControl,
    NetworkSecurity, IncidentResponse, MaturityAnalysisHistory
)
from django.contrib.auth.models import User
from django.db.models import Count, Sum
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
from io import BytesIO
import os
from django.conf import settings
from django.template.loader import render_to_string
import shutil
import tempfile
from datetime import datetime, timedelta
from django.template import RequestContext
from weasyprint import HTML

def compute_compliance_status(model_instances):
    """Compute overall compliance status based on model fields."""
    if not model_instances.exists():
        return {'Compliant': 0, 'Non-Compliant': 0, 'Partial': 0}
    
    status_counts = {'Compliant': 0, 'Non-Compliant': 0, 'Partial': 0}
    for instance in model_instances:
        fields_to_check = []
        if isinstance(instance, AccessControl):
            fields_to_check = ['mfa_implemented', 'strong_password_policy', 'role_based_access']
        elif isinstance(instance, NetworkSecurity):
            fields_to_check = ['firewall_review_periodic', 'dns_monitoring']
        elif isinstance(instance, IncidentResponse):
            fields_to_check = ['has_plan', 'dedicated_team', 'cyber_insurance']

        all_affirmative = all(getattr(instance, field, False) == True for field in fields_to_check if getattr(instance, field, None) is not None)
        none_affirmative = all(getattr(instance, field, False) == False for field in fields_to_check if getattr(instance, field, None) is not None)

        if all_affirmative:
            status_counts['Compliant'] += 1
        elif none_affirmative:
            status_counts['Non-Compliant'] += 1
        else:
            status_counts['Partial'] += 1
    
    return status_counts

def compute_instance_compliance_status(instance):
    """Compute compliance status for a single instance."""
    fields_to_check = []
    if isinstance(instance, AccessControl):
        fields_to_check = ['mfa_implemented', 'strong_password_policy', 'role_based_access']
    elif isinstance(instance, NetworkSecurity):
        fields_to_check = ['firewall_review_periodic', 'dns_monitoring']
    elif isinstance(instance, IncidentResponse):
        fields_to_check = ['has_plan', 'dedicated_team', 'cyber_insurance']

    all_affirmative = all(getattr(instance, field, False) == True for field in fields_to_check if getattr(instance, field, None) is not None)
    none_affirmative = all(getattr(instance, field, False) == False for field in fields_to_check if getattr(instance, field, None) is not None)

    if all_affirmative:
        return 'Compliant'
    elif none_affirmative:
        return 'Non-Compliant'
    else:
        return 'Partial'

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'assessments/login.html')

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()
    return render(request, 'assessments/signup.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    print(f"dashboard - User: {request.user}, Authenticated: {request.user.is_authenticated}")
    print(f"dashboard - Session ID: {request.session.session_key}")

    total_users = User.objects.count()
    active_users = User.objects.filter(last_login__gte=datetime.now() - timedelta(days=30)).count()
    total_organizations = Organization.objects.count()
    total_assessments = (
        MobileWebAssessment.objects.count() +
        APIAssessment.objects.count() +
        FirewallAssessment.objects.count() +
        PhishingAssessment.objects.count() +
        MaturityAssessment.objects.count() +
        NISTAssessment.objects.count() +
        AssetInventory.objects.count() +
        AccessControl.objects.count() +
        NetworkSecurity.objects.count() +
        IncidentResponse.objects.count()
    )

    mobile_web_counts = MobileWebAssessment.objects.values('compliance_status').annotate(count=Count('id'))
    api_counts = APIAssessment.objects.values('compliance_status').annotate(count=Count('id'))
    firewall_counts = FirewallAssessment.objects.values('compliance_status').annotate(count=Count('id'))
    nist_counts = NISTAssessment.objects.values('compliance_status').annotate(count=Count('id'))
    
    access_control_counts = compute_compliance_status(AccessControl.objects.all())
    network_security_counts = compute_compliance_status(NetworkSecurity.objects.all())
    incident_response_counts = compute_compliance_status(IncidentResponse.objects.all())
    
    maturity_levels = MaturityAssessment.objects.values('maturity_level').annotate(count=Count('id'))
    phishing_clicks = PhishingAssessment.objects.values('awareness_level').annotate(count=Count('id'))

    asset_inventory_data = AssetInventory.objects.aggregate(
        laptops=Sum('laptops'),
        mobile_devices=Sum('mobile_devices'),
        workstations=Sum('workstations'),
        physical_servers=Sum('physical_servers'),
        virtual_servers=Sum('virtual_servers')
    )
    asset_inventory_data = {k: v if v is not None else 0 for k, v in asset_inventory_data.items()}

    mobile_web_total = sum(item['count'] for item in mobile_web_counts)
    mobile_web_compliant = sum(item['count'] for item in mobile_web_counts if item['compliance_status'] == 'Compliant')
    mobile_web_compliance_percentage = (mobile_web_compliant / mobile_web_total * 100) if mobile_web_total > 0 else 0

    api_total = sum(item['count'] for item in api_counts)
    api_compliant = sum(item['count'] for item in api_counts if item['compliance_status'] == 'Compliant')
    api_compliance_percentage = (api_compliant / api_total * 100) if api_total > 0 else 0

    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)
    compliance_trend = []
    for i in range(6):
        month_start = start_date + timedelta(days=i*30)
        month_end = month_start + timedelta(days=30)
        mobile_web_month = MobileWebAssessment.objects.filter(
            created_at__range=(month_start, month_end)
        ).values('compliance_status').annotate(count=Count('id'))
        api_month = APIAssessment.objects.filter(
            created_at__range=(month_start, month_end)
        ).values('compliance_status').annotate(count=Count('id'))
        
        mobile_web_compliant = sum(item['count'] for item in mobile_web_month if item['compliance_status'] == 'Compliant')
        mobile_web_total = sum(item['count'] for item in mobile_web_month)
        mobile_web_percent = (mobile_web_compliant / mobile_web_total * 100) if mobile_web_total > 0 else 0

        api_compliant = sum(item['count'] for item in api_month if item['compliance_status'] == 'Compliant')
        api_total = sum(item['count'] for item in api_month)
        api_percent = (api_compliant / api_total * 100) if api_total > 0 else 0

        compliance_trend.append({
            'month': month_start.strftime('%b %Y'),
            'mobile_web': mobile_web_percent,
            'api': api_percent
        })

    organizations = Organization.objects.all()
    organization_compliance = []
    for org in organizations:
        mobile_web = MobileWebAssessment.objects.filter(organization=org).order_by('-id').first()
        api = APIAssessment.objects.filter(organization=org).order_by('-id').first()
        firewall = FirewallAssessment.objects.filter(organization=org).order_by('-id').first()
        phishing = PhishingAssessment.objects.filter(organization=org).order_by('-id').first()
        maturity = MaturityAssessment.objects.filter(organization=org).order_by('-id').first()
        access_control = AccessControl.objects.filter(organization=org).order_by('-id').first()
        network_security = NetworkSecurity.objects.filter(organization=org).order_by('-id').first()
        incident_response = IncidentResponse.objects.filter(organization=org).order_by('-id').first()

        org_data = {
            'name': org.name,
            'mobile_web': mobile_web.compliance_status if mobile_web else None,
            'api': api.compliance_status if api else None,
            'firewall': firewall.compliance_status if firewall else None,
            'phishing': phishing.awareness_level if phishing else None,
            'maturity': maturity.maturity_level if maturity else None,
            'access_control': compute_instance_compliance_status(access_control) if access_control else None,
            'network_security': compute_instance_compliance_status(network_security) if network_security else None,
            'incident_response': compute_instance_compliance_status(incident_response) if incident_response else None,
        }
        organization_compliance.append(org_data)

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_organizations': total_organizations,
        'total_assessments': total_assessments,
        'mobile_web_data': json.dumps(list(mobile_web_counts)),
        'api_data': json.dumps(list(api_counts)),
        'firewall_data': json.dumps(list(firewall_counts)),
        'nist_data': json.dumps(list(nist_counts)),
        'asset_inventory_data': json.dumps(asset_inventory_data),
        'access_control_data': json.dumps([{'compliance_status': k, 'count': v} for k, v in access_control_counts.items()]),
        'network_security_data': json.dumps([{'compliance_status': k, 'count': v} for k, v in network_security_counts.items()]),
        'incident_response_data': json.dumps([{'compliance_status': k, 'count': v} for k, v in incident_response_counts.items()]),
        'maturity_data': json.dumps(list(maturity_levels)),
        'phishing_data': json.dumps(list(phishing_clicks)),
        'mobile_web_compliance_percentage': mobile_web_compliance_percentage,
        'api_compliance_percentage': api_compliance_percentage,
        'compliance_trend_data': json.dumps(compliance_trend),
        'organization_compliance': organization_compliance,
    }
    return render(request, 'assessments/dashboard.html', context)

@login_required
def mobile_web_form(request):
    if request.method == 'POST':
        form = MobileWebForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = MobileWebForm()
    return render(request, 'assessments/mobile_web_form.html', {'form': form})

@login_required
def api_form(request):
    if request.method == 'POST':
        form = APIForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = APIForm()
    return render(request, 'assessments/api_form.html', {'form': form})

@login_required
def firewall_form(request):
    if request.method == 'POST':
        form = FirewallForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = FirewallForm()
    return render(request, 'assessments/firewall_form.html', {'form': form})

@login_required
def phishing_form(request):
    if request.method == 'POST':
        form = PhishingForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = PhishingForm()
    return render(request, 'assessments/phishing_form.html', {'form': form})

@login_required
def maturity_form(request):
    if request.method == 'POST':
        form = MaturityForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = MaturityForm()
    return render(request, 'assessments/maturity_form.html', {'form': form})

@login_required
def nist_form(request):
    if request.method == 'POST':
        form = NISTForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.assessor = request.user
            assessment.save()
            return redirect('dashboard')
    else:
        form = NISTForm()
    return render(request, 'assessments/nist_form.html', {'form': form})

@login_required
def organization_form(request):
    if request.method == 'POST':
        form = OrganizationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = OrganizationForm()
    return render(request, 'assessments/organization_form.html', {'form': form})

@login_required
def asset_inventory_form(request):
    if request.method == 'POST':
        form = AssetInventoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = AssetInventoryForm()
    return render(request, 'assessments/asset_inventory_form.html', {'form': form})

@login_required
def access_control_form(request):
    if request.method == 'POST':
        form = AccessControlForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = AccessControlForm()
    return render(request, 'assessments/access_control_form.html', {'form': form})

@login_required
def network_security_form(request):
    if request.method == 'POST':
        form = NetworkSecurityForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = NetworkSecurityForm()
    return render(request, 'assessments/network_security_form.html', {'form': form})

@login_required
def incident_response_form(request):
    if request.method == 'POST':
        form = IncidentResponseForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = IncidentResponseForm()
    return render(request, 'assessments/incident_response_form.html', {'form': form})

@login_required
def maturity_analysis(request):
    if request.method == 'POST':
        form = MaturityAnalysisForm(request.POST)
        if form.is_valid():
            responses = [
                int(form.cleaned_data[f'q{i}_response'])
                for i in range(10)
            ]
            weights = [
                float(form.cleaned_data[f'q{i}_weight'])
                for i in range(10)
            ]
            if any(r < 0 or r > 5 for r in responses):
                messages.error(request, 'Responses must be between 0 and 5.')
                return render(request, 'assessments/maturity_analysis.html', {'form': form})
            
            total_weight = sum(weights)
            weighted_scores = [r * w for r, w in zip(responses, weights)]
            average_score = sum(weighted_scores) / total_weight
            maturity_percentage = (average_score / 5) * 100
            maturity_levels = ['Unaware', 'Aware', 'Defined', 'Managed', 'Optimized', 'Mature']
            maturity_level = maturity_levels[int(average_score)]

            MaturityAnalysisHistory.objects.create(
                user=request.user,
                organization=form.cleaned_data['organization'],
                responses=responses,
                average_score=average_score,
                maturity_percentage=maturity_percentage,
                maturity_level=maturity_level
            )

            history = MaturityAnalysisHistory.objects.filter(user=request.user, organization=form.cleaned_data['organization'])
            scores = [h.average_score for h in history]
            percentages = [h.maturity_percentage for h in history]
            instances = list(range(1, len(scores) + 1))

            plt.figure(figsize=(6, 4))
            plt.plot(instances, scores, marker='o', label='Average Scores', color='blue')
            plt.plot(instances, percentages, marker='x', linestyle='--', label='Percentages', color='green')
            plt.title('Trend Analysis')
            plt.xlabel('Instances')
            plt.ylabel('Values')
            plt.legend()
            trend_buffer = BytesIO()
            plt.savefig(trend_buffer, format='png')
            plt.close()
            trend_buffer.seek(0)
            trend_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'trend.png')
            os.makedirs(os.path.dirname(trend_path), exist_ok=True)
            with open(trend_path, 'wb') as f:
                f.write(trend_buffer.read())

            plt.figure(figsize=(6, 4))
            level_counts = pd.Series([h.maturity_level for h in history]).value_counts()
            plt.pie(level_counts, labels=level_counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99', '#FFCC99', '#FF99CC', '#99CCCC'])
            plt.title('Maturity Levels Distribution')
            pie_buffer = BytesIO()
            plt.savefig(pie_buffer, format='png')
            plt.close()
            pie_buffer.seek(0)
            pie_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'pie.png')
            with open(pie_path, 'wb') as f:
                f.write(pie_buffer.read())

            context = {
                'form': form,
                'maturity_level': maturity_level,
                'maturity_percentage': f'{maturity_percentage:.2f}%',
                'trend_image': 'images/trend.png',
                'pie_image': 'images/pie.png'
            }
            return render(request, 'assessments/maturity_analysis.html', context)
    else:
        form = MaturityAnalysisForm()
    return render(request, 'assessments/maturity_analysis.html', {'form': form})

@login_required
def report_menu(request):
    print(f"report_menu - User: {request.user}, Authenticated: {request.user.is_authenticated}")
    print(f"report_menu - Session ID: {request.session.session_key}")

    organizations = Organization.objects.all()
    report_types = [
        ('mobile_web', 'Mobile & Web Apps'),
        ('api', 'APIs'),
        ('firewall', 'Firewall Rules'),
        ('phishing', 'Phishing Drills'),
        ('maturity', 'Maturity Analysis'),
        ('nist', 'NIST Compliance'),
        ('asset_inventory', 'Asset Inventory'),
        ('access_control', 'Access Control'),
        ('network_security', 'Network Security'),
        ('incident_response', 'Incident Response'),
        ('overall', 'Overall Report')
    ]
    if request.method == 'POST':
        print(f"report_menu POST - User: {request.user}, Authenticated: {request.user.is_authenticated}")
        org_id = request.POST.get('organization')
        report_type = request.POST.get('report_type')
        if org_id and report_type:
            request.session.modified = True
            print(f"report_menu POST - Redirecting to generate_report with org_id: {org_id}, report_type: {report_type}")
            return redirect('generate_report', org_id=org_id, report_type=report_type)
        messages.error(request, 'Please select an organization and report type.')
    return render(request, 'assessments/report_menu.html', {'organizations': organizations, 'report_types': report_types})

@login_required
def generate_report(request, org_id, report_type):
    print(f"generate_report - User: {request.user}, Authenticated: {request.user.is_authenticated}")
    print(f"generate_report - Session ID: {request.session.session_key}")

    if not request.user.is_authenticated:
        messages.error(request, "You have been logged out. Please log in again to generate the report.")
        return redirect('login')

    organization = Organization.objects.get(id=org_id)
    context = {'organization': organization}
    images = {}
    temp_dir = '/root/CyberSecAssessment/temp'
    os.makedirs(temp_dir, exist_ok=True)

    context['current_datetime'] = datetime.now()
    report_type_display = report_type.replace('_', ' ').title()
    context['report_type_display'] = report_type_display

    # Initialize assessments as an empty queryset to avoid UnboundLocalError
    assessments = None
    latest_assessment = None
    details = {}

    if report_type == 'mobile_web':
        assessments = MobileWebAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Compliance Status': latest_assessment.compliance_status,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        counts = pd.Series([a.compliance_status for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Mobile & Web Compliance Status')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'mobile_web_pie.png')
        os.makedirs(os.path.dirname(image_path), exist_ok=True)
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['mobile_web'] = 'images/mobile_web_pie.png'

    elif report_type == 'api':
        assessments = APIAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Compliance Status': latest_assessment.compliance_status,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        counts = pd.Series([a.compliance_status for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('API Compliance Status')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'api_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['api'] = 'images/api_pie.png'

    elif report_type == 'firewall':
        assessments = FirewallAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Compliance Status': latest_assessment.compliance_status,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        counts = pd.Series([a.compliance_status for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Firewall Compliance Status')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'firewall_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['firewall'] = 'images/firewall_pie.png'

    elif report_type == 'phishing':
        assessments = PhishingAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Awareness Level': latest_assessment.awareness_level,
                'Click Rate': f"{latest_assessment.click_rate}%",
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        click_rates = [a.click_rate for a in assessments]
        plt.figure(figsize=(6, 4))
        plt.hist(click_rates, bins=5, color='skyblue', edgecolor='black')
        plt.title('Phishing Click Rate Distribution')
        plt.xlabel('Click Rate (%)')
        plt.ylabel('Frequency')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'phishing_hist.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['phishing'] = 'images/phishing_hist.png'

    elif report_type == 'maturity':
        assessments = MaturityAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Maturity Level': latest_assessment.maturity_level,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        counts = pd.Series([a.maturity_level for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.bar(counts.index, counts.values, color='purple', edgecolor='black')
        plt.title('Maturity Levels Distribution')
        plt.xlabel('Maturity Level')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'maturity_bar.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['maturity'] = 'images/maturity_bar.png'

    elif report_type == 'nist':
        assessments = NISTAssessment.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Compliance Status': latest_assessment.compliance_status,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            if hasattr(latest_assessment, 'created_at'):
                details['Created At'] = latest_assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        context['assessments'] = assessments
        counts = pd.Series([a.compliance_status for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('NIST Compliance Status')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'nist_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['nist'] = 'images/nist_pie.png'

    elif report_type == 'asset_inventory':
        assessments = AssetInventory.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            details = {
                'Laptops': latest_assessment.laptops,
                'Mobile Devices': latest_assessment.mobile_devices,
                'Workstations': latest_assessment.workstations,
                'Physical Servers': latest_assessment.physical_servers,
                'Virtual Servers': latest_assessment.virtual_servers,
                'Cloud Services': latest_assessment.cloud_services,
                'Core Systems': latest_assessment.core_systems,
            }
            # AssetInventory does not have created_at
        context['assessments'] = assessments
        asset_types = ['laptops', 'mobile_devices', 'workstations', 'physical_servers', 'virtual_servers']
        counts = pd.Series([getattr(a, attr) for a in assessments for attr in asset_types if getattr(a, attr) is not None])
        if counts.sum() > 0:
            asset_counts = pd.Series({attr: sum(getattr(a, attr, 0) for a in assessments) for attr in asset_types})
            plt.figure(figsize=(6, 4))
            plt.pie(asset_counts, labels=asset_counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99', '#FFCC99', '#FF99CC'])
            plt.title('Asset Inventory Distribution')
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            buffer.seek(0)
            image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'asset_inventory_pie.png')
            with open(image_path, 'wb') as f:
                f.write(buffer.read())
            images['asset_inventory'] = 'images/asset_inventory_pie.png'

    elif report_type == 'access_control':
        assessments = AccessControl.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            compliance_status = compute_instance_compliance_status(latest_assessment)
            details = {
                'Compliance Status': compliance_status,
                'MFA Implemented': latest_assessment.mfa_implemented,
                'Onboarding Process': latest_assessment.onboarding_process,
                'Offboarding Process': latest_assessment.offboarding_process,
                'Privileged Users': latest_assessment.privileged_users,
                'Role-Based Access': latest_assessment.role_based_access,
                'Strong Password Policy': latest_assessment.strong_password_policy,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            # AccessControl does not have created_at
        context['assessments'] = assessments
        counts = pd.Series([compute_instance_compliance_status(a) for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Access Control Compliance')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'access_control_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['access_control'] = 'images/access_control_pie.png'

    elif report_type == 'network_security':
        assessments = NetworkSecurity.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            compliance_status = compute_instance_compliance_status(latest_assessment)
            details = {
                'Compliance Status': compliance_status,
                'Firewall Review Periodic': latest_assessment.firewall_review_periodic,
                'DNS Monitoring': latest_assessment.dns_monitoring,
                'Notes': latest_assessment.notes or 'No notes available',
            }
            # NetworkSecurity does not have created_at
        context['assessments'] = assessments
        counts = pd.Series([compute_instance_compliance_status(a) for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Network Security Compliance')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'network_security_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['network_security'] = 'images/network_security_pie.png'

    elif report_type == 'incident_response':
        assessments = IncidentResponse.objects.filter(organization=organization).order_by('-id')
        if assessments.exists():
            latest_assessment = assessments.first()
            compliance_status = compute_instance_compliance_status(latest_assessment)
            details = {
                'Compliance Status': compliance_status,
                'Has Plan': latest_assessment.has_plan,
                'Dedicated Team': latest_assessment.dedicated_team,
                'Cyber Insurance': latest_assessment.cyber_insurance,
                'Notes': 'No notes available',  # IncidentResponse does not have a notes field
            }
            # IncidentResponse does not have created_at
        context['assessments'] = assessments
        counts = pd.Series([compute_instance_compliance_status(a) for a in assessments]).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Incident Response Compliance')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'incident_response_pie.png')
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['incident_response'] = 'images/incident_response_pie.png'

    elif report_type == 'overall':
        assessment_types = {
            'mobile_web': MobileWebAssessment.objects.filter(organization=organization).order_by('-id'),
            'api': APIAssessment.objects.filter(organization=organization).order_by('-id'),
            'firewall': FirewallAssessment.objects.filter(organization=organization).order_by('-id'),
            'phishing': PhishingAssessment.objects.filter(organization=organization).order_by('-id'),
            'maturity': MaturityAssessment.objects.filter(organization=organization).order_by('-id'),
            'nist': NISTAssessment.objects.filter(organization=organization).order_by('-id'),
            'asset_inventory': AssetInventory.objects.filter(organization=organization).order_by('-id'),
            'access_control': AccessControl.objects.filter(organization=organization).order_by('-id'),
            'network_security': NetworkSecurity.objects.filter(organization=organization).order_by('-id'),
            'incident_response': IncidentResponse.objects.filter(organization=organization).order_by('-id')
        }
        context.update(assessment_types)

        all_compliance = []
        compliance_breakdown = {}
        for key, assessments_list in assessment_types.items():
            if key in ['mobile_web', 'api', 'firewall', 'nist']:
                compliance_breakdown[key] = pd.Series([a.compliance_status for a in assessments_list]).value_counts().to_dict()
                all_compliance.extend([a.compliance_status for a in assessments_list])
            elif key in ['access_control', 'network_security', 'incident_response']:
                compliance_breakdown[key] = pd.Series([compute_instance_compliance_status(a) for a in assessments_list]).value_counts().to_dict()
                all_compliance.extend([compute_instance_compliance_status(a) for a in assessments_list])
            elif key == 'maturity':
                compliance_breakdown[key] = pd.Series([a.maturity_level for a in assessments_list]).value_counts().to_dict()
            elif key == 'phishing':
                compliance_breakdown[key] = pd.Series([a.awareness_level for a in assessments_list]).value_counts().to_dict()
            elif key == 'asset_inventory':
                asset_types = ['laptops', 'mobile_devices', 'workstations', 'physical_servers', 'virtual_servers']
                compliance_breakdown[key] = {attr: sum(getattr(a, attr, 0) for a in assessments_list) for attr in asset_types}

        counts = pd.Series(all_compliance).value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=['#FF9999', '#66B2FF', '#99FF99'])
        plt.title('Overall Compliance Status')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        buffer.seek(0)
        image_path = os.path.join(settings.STATICFILES_DIRS[0], 'images', 'overall_pie.png')
        os.makedirs(os.path.dirname(image_path), exist_ok=True)
        with open(image_path, 'wb') as f:
            f.write(buffer.read())
        images['overall_pie'] = 'images/overall_pie.png'

        formatted_assessment_types = {key.replace('_', ' ').title(): value for key, value in assessment_types.items()}
        context['formatted_assessment_types'] = formatted_assessment_types
        context['compliance_breakdown'] = compliance_breakdown

    recommendations = []
    if report_type != 'overall' and assessments:
        for assessment in context['assessments']:
            if hasattr(assessment, 'compliance_status'):
                status = assessment.compliance_status
            elif report_type in ['access_control', 'network_security', 'incident_response']:
                status = compute_instance_compliance_status(assessment)
            else:
                status = None

            if status in ['Non-Compliant', 'Partial']:
                notes = assessment.notes if hasattr(assessment, 'notes') else 'identified issues'
                recommendations.append(f"Address {notes} in {report_type_display} to improve compliance.")
            elif hasattr(assessment, 'maturity_level') and assessment.maturity_level in ['Non-existent', 'Compliance Focused']:
                recommendations.append(f"Enhance training and processes for {report_type_display} to advance maturity beyond {assessment.maturity_level}.")
            elif hasattr(assessment, 'awareness_level') and assessment.awareness_level in ['Low', 'Moderate']:
                recommendations.append(f"Improve {report_type_display} awareness to exceed {assessment.awareness_level} level.")
    if report_type == 'overall':
        for key, assessments_list in context['formatted_assessment_types'].items():
            for assessment in assessments_list:
                if hasattr(assessment, 'compliance_status'):
                    status = assessment.compliance_status
                elif key.lower().replace(' ', '_') in ['access_control', 'network_security', 'incident_response']:
                    status = compute_instance_compliance_status(assessment)
                else:
                    status = None

                if status in ['Non-Compliant', 'Partial']:
                    notes = assessment.notes if hasattr(assessment, 'notes') else 'identified issues'
                    recommendations.append(f"Address {notes} in {key} to improve overall compliance.")
                elif hasattr(assessment, 'maturity_level') and assessment.maturity_level in ['Non-existent', 'Compliance Focused']:
                    recommendations.append(f"Enhance training and processes for {key} to advance maturity beyond {assessment.maturity_level}.")
                elif hasattr(assessment, 'awareness_level') and assessment.awareness_level in ['Low', 'Moderate']:
                    recommendations.append(f"Improve {key} awareness to exceed {assessment.awareness_level} level.")

    context['recommendations'] = recommendations
    context['images'] = images
    context['report_type'] = report_type
    context['details'] = details

    for image_key, image_path in images.items():
        src_path = os.path.join(settings.STATICFILES_DIRS[0], image_path)
        dst_path = os.path.join(temp_dir, image_path)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)
        print(f"Copied {src_path} to {dst_path}")

    pdf_context = context.copy()
    pdf_images = {key: os.path.join(settings.STATICFILES_DIRS[0], path) for key, path in images.items()}
    pdf_context['images'] = pdf_images

    html_content = render_to_string('assessments/report.html', context, request=request)
    pdf_html_content = render_to_string('assessments/report.html', pdf_context, request=request)

    if request.method == 'POST' and 'download_pdf' in request.POST:
        print(f"generate_report POST - User: {request.user}, Authenticated: {request.user.is_authenticated}")
        pdf_path = os.path.join(temp_dir, f'{organization.name}_{report_type}_report.pdf')
        HTML(string=pdf_html_content, base_url=settings.STATICFILES_DIRS[0]).write_pdf(pdf_path)
        with open(pdf_path, 'rb') as f:
            response = FileResponse(f, as_attachment=True, filename=f'{organization.name}_{report_type}_report.pdf')
            return response

    return HttpResponse(html_content)
