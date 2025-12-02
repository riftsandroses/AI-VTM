from django.contrib import admin
from .models import (
    Organization, Asset, Vulnerability, TesterArtifact,
    AIRemediation, RemediationFeedback, RemediationChat, 
    ChatMessage, RemediationUpdate, VulnerabilityRiskAssessment, 
    AssetRiskAssessment, OrganizationRiskAssessment,
    RiskAssessmentHistory, RiskContext, RiskOverrideHistory, 
    RiskContextChat
)
from .risk_scoring_service import RiskScoringService
from .models import GlobalChatHistory

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


class ChatMessageInline(admin.TabularInline):
    model = ChatMessage
    extra = 0
    fields = ['role', 'content', 'created_at']
    readonly_fields = ['created_at']
    can_delete = False


@admin.register(RemediationChat)
class RemediationChatAdmin(admin.ModelAdmin):
    list_display = ['remediation', 'session_id', 'is_active', 'message_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['remediation__vulnerability__control_title', 'session_id']
    readonly_fields = ['id', 'session_id', 'created_at', 'updated_at']
    inlines = [ChatMessageInline]
    
    def message_count(self, obj):
        return obj.messages.count()
    message_count.short_description = 'Messages'


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ['chat_session', 'role', 'content_preview', 'created_at']
    list_filter = ['role', 'created_at']
    search_fields = ['content', 'chat_session__remediation__vulnerability__control_title']
    readonly_fields = ['id', 'created_at']
    
    def content_preview(self, obj):
        return obj.content[:100] + '...' if len(obj.content) > 100 else obj.content
    content_preview.short_description = 'Content'


@admin.register(RemediationUpdate)
class RemediationUpdateAdmin(admin.ModelAdmin):
    list_display = ['remediation', 'chat_session', 'update_reason_preview', 'created_at']
    list_filter = ['created_at']
    search_fields = ['remediation__vulnerability__control_title', 'update_reason']
    readonly_fields = ['id', 'created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'remediation', 'chat_session', 'update_reason')
        }),
        ('Changes', {
            'fields': ('previous_steps', 'updated_steps')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )
    
    def update_reason_preview(self, obj):
        return obj.update_reason[:50] + '...' if len(obj.update_reason) > 50 else obj.update_reason
    update_reason_preview.short_description = 'Reason'


# =========================
# ★ UPDATED RISK ADMIN SECTIONS WITH CONTEXT + OVERRIDE
# =========================


@admin.register(VulnerabilityRiskAssessment)
class VulnerabilityRiskAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'vulnerability_title', 'risk_score', 'risk_level', 
        'priority', 'calculated_at', 'is_overridden',
        'has_contexts', 'has_override'
    ]
    list_filter = ['risk_level', 'priority', 'is_overridden', 'calculated_at']
    search_fields = ['vulnerability__control_title', 'reasoning', 'key_risk_factors']
    readonly_fields = ['id', 'vulnerability', 'model_used', 'calculated_at', 'last_updated']

    def has_contexts(self, obj):
        return '✓' if getattr(obj, "has_active_contexts", False) else '✗'
    has_contexts.short_description = 'Contexts'
    has_contexts.boolean = True

    def has_override(self, obj):
        return '✓' if getattr(obj, "has_manual_override", False) else '✗'
    has_override.short_description = 'Override'
    has_override.boolean = True
        
    fieldsets = (
        ('Vulnerability', {'fields': ('id', 'vulnerability')}),
        ('Risk Assessment', {'fields': ('risk_score', 'risk_level', 'priority', 'recommended_timeline')}),
        ('AI Analysis', {'fields': ('reasoning', 'key_risk_factors', 'model_used')}),
        ('Override Information', {
            'fields': ('is_overridden', 'override_reason', 'overridden_by', 'overridden_at'),
            'classes': ('collapse',)
        }),
        ('Context & Override Information', {
            'fields': ('has_active_contexts', 'active_context_count', 'has_manual_override', 'current_override_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {'fields': ('calculated_at', 'last_updated')}),
    )

    def vulnerability_title(self, obj):
        return obj.vulnerability.control_title
    vulnerability_title.short_description = 'Vulnerability'
    vulnerability_title.admin_order_field = 'vulnerability__control_title'


    actions = ['recalculate_risk']
    
    def recalculate_risk(self, request, queryset):
        risk_service = RiskScoringService()
        updated = 0
        
        for assessment in queryset:
            try:
                risk_data = risk_service.calculate_vulnerability_risk(assessment.vulnerability)
                for key, value in risk_data.items():
                    setattr(assessment, key, value)
                assessment.save()
                updated += 1
            except Exception as e:
                self.message_user(request, f"Error updating {assessment.vulnerability.control_title}: {str(e)}", level='ERROR')
        
        self.message_user(request, f"Successfully recalculated {updated} risk assessments.")
    recalculate_risk.short_description = "Recalculate selected risk assessments"



@admin.register(AssetRiskAssessment)
class AssetRiskAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'asset_name', 'risk_score', 'risk_level', 
        'priority', 'calculated_at', 'is_overridden',
        'has_contexts', 'has_override'
    ]
    list_filter = ['risk_level', 'priority', 'is_overridden', 'calculated_at']
    search_fields = ['asset__name', 'reasoning', 'key_risk_factors']
    readonly_fields = ['id', 'asset', 'model_used', 'calculated_at', 'last_updated', 'vulnerability_summary']

    def has_contexts(self, obj):
        return '✓' if getattr(obj, "has_active_contexts", False) else '✗'
    has_contexts.short_description = 'Contexts'
    has_contexts.boolean = True

    def has_override(self, obj):
        return '✓' if getattr(obj, "has_manual_override", False) else '✗'
    has_override.short_description = 'Override'
    has_override.boolean = True

    fieldsets = (
        ('Asset', {'fields': ('id', 'asset')}),
        ('Risk Assessment', {'fields': ('risk_score', 'risk_level', 'priority', 'estimated_remediation_effort')}),
        ('AI Analysis', {'fields': ('reasoning', 'key_risk_factors', 'remediation_priority', 'model_used')}),
        ('Vulnerability Summary', {'fields': ('vulnerability_summary',)}),
        ('Override Information', {
            'fields': ('is_overridden', 'override_reason', 'overridden_by', 'overridden_at'),
            'classes': ('collapse',)
        }),
        ('Context & Override Information', {
            'fields': ('has_active_contexts', 'active_context_count', 'has_manual_override', 'current_override_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {'fields': ('calculated_at', 'last_updated')}),
    )

    def asset_name(self, obj):
        return obj.asset.name
    asset_name.short_description = 'Asset'
    asset_name.admin_order_field = 'asset__name'

    actions = ['recalculate_risk']
    
    def recalculate_risk(self, request, queryset):
        risk_service = RiskScoringService()
        updated = 0
        
        for assessment in queryset:
            try:
                risk_data = risk_service.calculate_asset_risk(assessment.asset)
                for key, value in risk_data.items():
                    setattr(assessment, key, value)
                assessment.save()
                updated += 1
            except Exception as e:
                self.message_user(request, f"Error updating {assessment.asset.name}: {str(e)}", level='ERROR')
        
        self.message_user(request, f"Successfully recalculated {updated} risk assessments.")
    recalculate_risk.short_description = "Recalculate selected risk assessments"



@admin.register(OrganizationRiskAssessment)
class OrganizationRiskAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'organization_name', 'risk_score', 'risk_level', 
        'calculated_at', 'is_overridden',
        'has_contexts', 'has_override'
    ]
    list_filter = ['risk_level', 'is_overridden', 'calculated_at']
    search_fields = ['organization__name', 'reasoning', 'key_risk_factors']
    readonly_fields = ['id', 'organization', 'model_used', 'calculated_at', 'last_updated', 'asset_summary']

    def has_contexts(self, obj):
        return '✓' if getattr(obj, "has_active_contexts", False) else '✗'
    has_contexts.short_description = 'Contexts'
    has_contexts.boolean = True

    def has_override(self, obj):
        return '✓' if getattr(obj, "has_manual_override", False) else '✗'
    has_override.short_description = 'Override'
    has_override.boolean = True

    fieldsets = (
        ('Organization', {'fields': ('id', 'organization')}),
        ('Risk Assessment', {'fields': ('risk_score', 'risk_level', 'priority')}),
        ('AI Analysis', {
            'fields': ('reasoning', 'key_risk_factors', 'strategic_recommendations', 'focus_areas', 'model_used')
        }),
        ('Asset Summary', {'fields': ('asset_summary',)}),
        ('Override Information', {
            'fields': ('is_overridden', 'override_reason', 'overridden_by', 'overridden_at'),
            'classes': ('collapse',)
        }),
        ('Context & Override Information', {
            'fields': ('has_active_contexts', 'active_context_count', 'has_manual_override', 'current_override_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {'fields': ('calculated_at', 'last_updated')}),
    )

    def organization_name(self, obj):
        return obj.organization.name
    organization_name.short_description = 'Organization'
    organization_name.admin_order_field = 'organization__name'

    actions = ['recalculate_risk']
    
    def recalculate_risk(self, request, queryset):
        risk_service = RiskScoringService()
        updated = 0
        
        for assessment in queryset:
            try:
                risk_data = risk_service.calculate_organization_risk(assessment.organization)
                for key, value in risk_data.items():
                    setattr(assessment, key, value)
                assessment.save()
                updated += 1
            except Exception as e:
                self.message_user(request, f"Error updating {assessment.organization.name}: {str(e)}", level='ERROR')
        
        self.message_user(request, f"Successfully recalculated {updated} risk assessments.")
    recalculate_risk.short_description = "Recalculate selected risk assessments"



@admin.register(RiskAssessmentHistory)
class RiskAssessmentHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'object_name', 'assessment_type', 
        'previous_risk_score', 'new_risk_score', 
        'risk_score_change', 'created_at'
    ]
    list_filter = ['assessment_type', 'created_at', 'new_risk_level']
    search_fields = ['object_name', 'change_reason']
    readonly_fields = [
        'id', 'assessment_type', 'object_id', 'object_name',
        'previous_risk_score', 'new_risk_score', 
        'previous_risk_level', 'new_risk_level',
        'change_reason', 'created_at'
    ]
    
    def risk_score_change(self, obj):
        if obj.previous_risk_score is not None:
            change = obj.new_risk_score - obj.previous_risk_score
            return f"+{change}" if change > 0 else str(change)
        return "N/A"
    risk_score_change.short_description = 'Change'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False   


@admin.register(RiskContext)
class RiskContextAdmin(admin.ModelAdmin):
    list_display = [
        'context_type', 'object_id', 'added_by', 'added_at', 
        'is_active', 'resulting_risk_score'
    ]
    list_filter = ['context_type', 'is_active', 'added_at']
    search_fields = ['context_text', 'added_by']
    readonly_fields = [
        'id', 'added_at', 'resulting_risk_score', 
        'resulting_risk_level', 'resulting_priority'
    ]
    
    fieldsets = (
        ('Object Information', {'fields': ('id', 'context_type', 'object_id')}),
        ('Context', {'fields': ('context_text', 'is_active')}),
        ('Added By', {'fields': ('added_by', 'added_at')}),
        ('Resulting Risk', {
            'fields': ('resulting_risk_score', 'resulting_risk_level', 'resulting_priority'),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        return False



@admin.register(RiskOverrideHistory)
class RiskOverrideHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'override_type', 'object_id', 'action', 
        'previous_risk_score', 'new_risk_score', 
        'risk_change', 'performed_by', 'performed_at',
        'is_current_state'
    ]
    list_filter = ['override_type', 'action', 'is_current_state', 'performed_at']
    search_fields = ['reason', 'performed_by']
    readonly_fields = [
        'id', 'override_type', 'object_id', 'action',
        'previous_risk_score', 'new_risk_score',
        'previous_risk_level', 'new_risk_level',
        'previous_priority', 'new_priority',
        'reason', 'performed_by', 'performed_at'
    ]
    
    fieldsets = (
        ('Override Information', {
            'fields': ('id', 'override_type', 'object_id', 'action', 'is_current_state')
        }),
        ('Previous State', {'fields': ('previous_risk_score', 'previous_risk_level', 'previous_priority')}),
        ('New State', {'fields': ('new_risk_score', 'new_risk_level', 'new_priority')}),
        ('Details', {'fields': ('reason', 'performed_by', 'performed_at')}),
    )
    
    def risk_change(self, obj):
        if obj.previous_risk_score is not None:
            change = obj.new_risk_score - obj.previous_risk_score
            return f"+{change}" if change > 0 else str(change)
        return "N/A"
    risk_change.short_description = 'Risk Change'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return True



@admin.register(RiskContextChat)
class RiskContextChatAdmin(admin.ModelAdmin):
    list_display = [
        'session_id', 'source_context', 'similar_count',
        'user_approved', 'is_active', 'created_at'
    ]
    list_filter = ['user_approved', 'is_active', 'created_at']
    search_fields = ['session_id', 'user_response']
    readonly_fields = [
        'id', 'session_id', 'source_context', 'similar_vulnerabilities',
        'contexts_applied', 'created_at', 'updated_at'
    ]
    
    fieldsets = (
        ('Chat Session', {'fields': ('id', 'session_id', 'is_active')}),
        ('Source Context', {'fields': ('source_context',)}),
        ('Similar Vulnerabilities', {'fields': ('similar_vulnerabilities',)}),
        ('User Decision', {'fields': ('user_approved', 'user_response')}),
        ('Application Results', {'fields': ('contexts_applied',)}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    def similar_count(self, obj):
        return len(obj.similar_vulnerabilities) if obj.similar_vulnerabilities else 0
    similar_count.short_description = 'Similar Vulns'
    
    def has_add_permission(self, request):
        return False


@admin.register(GlobalChatHistory)
class GlobalChatHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'query_preview', 'organization', 'query_type', 
        'created_at', 'was_helpful'
    ]
    list_filter = ['query_type', 'was_helpful', 'created_at', 'organization']
    search_fields = ['query', 'answer', 'intent']
    readonly_fields = [
        'id', 'query', 'intent', 'query_type', 'answer', 
        'insights', 'summary_stats', 'visualization_config', 
        'raw_data', 'user_identifier', 'session_id', 'created_at'
    ]
    
    fieldsets = (
        ('Query Information', {
            'fields': ('id', 'organization', 'query', 'intent', 'query_type')
        }),
        ('Response', {
            'fields': ('answer', 'insights', 'summary_stats')
        }),
        ('Visualization', {
            'fields': ('visualization_config',),
            'classes': ('collapse',)
        }),
        ('Raw Data', {
            'fields': ('raw_data',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('user_identifier', 'session_id', 'created_at')
        }),
        ('Feedback', {
            'fields': ('was_helpful', 'feedback_comments')
        }),
    )
    
    def query_preview(self, obj):
        return obj.query[:100] + '...' if len(obj.query) > 100 else obj.query
    query_preview.short_description = 'Query'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        # Only allow changing feedback
        return True