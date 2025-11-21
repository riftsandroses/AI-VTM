# admin.py
from django.contrib import admin
from .models import (
    Organization, Asset, Vulnerability, TesterArtifact,
    AIRemediation, RemediationFeedback
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at', 'asset_count']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    def asset_count(self, obj):
        return obj.assets.count()
    asset_count.short_description = 'Assets'


class TesterArtifactInline(admin.TabularInline):
    model = TesterArtifact
    extra = 1
    fields = ['file', 'description', 'uploaded_at']
    readonly_fields = ['uploaded_at']


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ['name', 'organization', 'asset_type', 'vulnerability_count', 'created_at']
    list_filter = ['asset_type', 'organization']
    search_fields = ['name', 'description', 'technology_stack']
    readonly_fields = ['id', 'created_at', 'updated_at']
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'organization', 'name', 'asset_type', 'description')
        }),
        ('Technical Details', {
            'fields': ('technology_stack', 'os_version', 'framework_version')
        }),
        ('Network Information (Sensitive)', {
            'fields': ('ip_address', 'url', 'internal_hostname'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def vulnerability_count(self, obj):
        return obj.vulnerabilities.count()
    vulnerability_count.short_description = 'Vulnerabilities'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['control_title', 'asset', 'severity', 'category', 'created_at']
    list_filter = ['severity', 'category', 'owasp']
    search_fields = ['control_title', 'control_description', 'cve_id', 'cwe_id']
    readonly_fields = ['id', 'created_at', 'updated_at']
    inlines = [TesterArtifactInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'asset', 'control_title', 'severity', 'category')
        }),
        ('Vulnerability Details', {
            'fields': ('control_description', 'control_impact', 'control_recommendation')
        }),
        ('Classification', {
            'fields': ('owasp', 'cve_id', 'cwe_id')
        }),
        ('Affected Systems', {
            'fields': ('affected_devices',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )


@admin.register(TesterArtifact)
class TesterArtifactAdmin(admin.ModelAdmin):
    list_display = ['vulnerability', 'description', 'uploaded_at']
    list_filter = ['uploaded_at']
    search_fields = ['vulnerability__control_title', 'description']
    readonly_fields = ['id', 'uploaded_at']


class RemediationFeedbackInline(admin.TabularInline):
    model = RemediationFeedback
    extra = 0
    fields = ['was_helpful', 'comments', 'stored_in_vector_db', 'created_at']
    readonly_fields = ['created_at', 'stored_in_vector_db']


@admin.register(AIRemediation)
class AIRemediationAdmin(admin.ModelAdmin):
    list_display = ['vulnerability', 'model_used', 'is_helpful', 'regeneration_count', 'created_at']
    list_filter = ['is_helpful', 'model_used', 'created_at']
    search_fields = ['vulnerability__control_title', 'remediation_steps']
    readonly_fields = ['id', 'created_at', 'model_used']
    inlines = [RemediationFeedbackInline]
    
    fieldsets = (
        ('Vulnerability', {
            'fields': ('id', 'vulnerability')
        }),
        ('AI Generation', {
            'fields': ('model_used', 'regeneration_count', 'prompt_used', 'remediation_steps')
        }),
        ('Feedback', {
            'fields': ('is_helpful', 'user_feedback', 'user_provided_steps')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )


@admin.register(RemediationFeedback)
class RemediationFeedbackAdmin(admin.ModelAdmin):
    list_display = ['remediation', 'was_helpful', 'stored_in_vector_db', 'created_at']
    list_filter = ['was_helpful', 'stored_in_vector_db', 'created_at']
    search_fields = ['comments', 'user_steps']
    readonly_fields = ['id', 'created_at', 'stored_in_vector_db', 'vector_db_id']
    
    fieldsets = (
        ('Remediation', {
            'fields': ('id', 'remediation')
        }),
        ('Feedback', {
            'fields': ('was_helpful', 'comments', 'user_steps')
        }),
        ('Vector DB', {
            'fields': ('stored_in_vector_db', 'vector_db_id')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )