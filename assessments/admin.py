from django.contrib import admin
from .models import (
    Organization, MobileWebAssessment, APIAssessment, FirewallAssessment,
    PhishingAssessment, MaturityAssessment, NISTAssessment, AssetInventory,
    SecurityTool, AccessControl, NetworkSecurity, IncidentResponse
)

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'industry', 'employee_count', 'created_at')
    search_fields = ('name', 'industry')

@admin.register(MobileWebAssessment)
class MobileWebAssessmentAdmin(admin.ModelAdmin):
    list_display = ('app_name', 'organization', 'compliance_status', 'date_completed')
    list_filter = ('compliance_status', 'platform')
    search_fields = ('app_name', 'organization__name')

@admin.register(APIAssessment)
class APIAssessmentAdmin(admin.ModelAdmin):
    list_display = ('api_name', 'organization', 'compliance_status', 'is_internal')
    list_filter = ('compliance_status', 'is_internal')
    search_fields = ('api_name', 'organization__name')

@admin.register(FirewallAssessment)
class FirewallAssessmentAdmin(admin.ModelAdmin):
    list_display = ('firewall_type', 'organization', 'compliance_status', 'last_review_date')
    list_filter = ('compliance_status',)
    search_fields = ('firewall_type', 'organization__name')

@admin.register(PhishingAssessment)
class PhishingAssessmentAdmin(admin.ModelAdmin):
    list_display = ('organization', 'awareness_level', 'click_rate', 'date_completed')
    list_filter = ('awareness_level',)
    search_fields = ('organization__name',)

@admin.register(MaturityAssessment)
class MaturityAssessmentAdmin(admin.ModelAdmin):
    list_display = ('organization', 'maturity_level', 'training_frequency', 'date_completed')
    list_filter = ('maturity_level', 'training_frequency')
    search_fields = ('organization__name',)

@admin.register(NISTAssessment)
class NISTAssessmentAdmin(admin.ModelAdmin):
    list_display = ('control_id', 'organization', 'compliance_status', 'control_family')
    list_filter = ('compliance_status', 'control_family')
    search_fields = ('control_id', 'organization__name')

@admin.register(AssetInventory)
class AssetInventoryAdmin(admin.ModelAdmin):
    list_display = ('organization', 'workstations', 'laptops', 'mobile_devices')
    search_fields = ('organization__name',)

@admin.register(SecurityTool)
class SecurityToolAdmin(admin.ModelAdmin):
    list_display = ('tool_name', 'tool_type', 'organization', 'in_use')
    list_filter = ('tool_type', 'in_use')
    search_fields = ('tool_name', 'organization__name')

@admin.register(AccessControl)
class AccessControlAdmin(admin.ModelAdmin):
    list_display = ('organization', 'privileged_users', 'mfa_implemented')
    search_fields = ('organization__name',)

@admin.register(NetworkSecurity)
class NetworkSecurityAdmin(admin.ModelAdmin):
    list_display = ('organization', 'vlan_count', 'firewall_count')
    search_fields = ('organization__name',)

@admin.register(IncidentResponse)
class IncidentResponseAdmin(admin.ModelAdmin):
    list_display = ('organization', 'has_plan', 'business_impact')
    search_fields = ('organization__name',)