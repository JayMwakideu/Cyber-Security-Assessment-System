from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('mobile-web-form/', views.mobile_web_form, name='mobile_web_form'),
    path('api-form/', views.api_form, name='api_form'),
    path('firewall-form/', views.firewall_form, name='firewall_form'),
    path('phishing-form/', views.phishing_form, name='phishing_form'),
    path('maturity-form/', views.maturity_form, name='maturity_form'),
    path('nist-form/', views.nist_form, name='nist_form'),
    path('organization-form/', views.organization_form, name='organization_form'),
    path('asset-inventory-form/', views.asset_inventory_form, name='asset_inventory_form'),
    path('access-control-form/', views.access_control_form, name='access_control_form'),
    path('network-security-form/', views.network_security_form, name='network_security_form'),
    path('incident-response-form/', views.incident_response_form, name='incident_response_form'),
    path('maturity-analysis/', views.maturity_analysis, name='maturity_analysis'),
    path('report-menu/', views.report_menu, name='report_menu'),
    path('report/<int:org_id>/<str:report_type>/', views.generate_report, name='generate_report'),
]