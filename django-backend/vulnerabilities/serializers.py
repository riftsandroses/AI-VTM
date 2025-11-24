from rest_framework import serializers
from .models import (
    Organization, Asset, Vulnerability, TesterArtifact,
    AIRemediation, RemediationFeedback, RemediationChat, ChatMessage,
    RemediationUpdate, VulnerabilityRiskAssessment, AssetRiskAssessment, 
    OrganizationRiskAssessment, RiskAssessmentHistory
)


class OrganizationSerializer(serializers.ModelSerializer):
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'description', 'created_at', 'updated_at', 'asset_count']

    def get_asset_count(self, obj):
        return obj.assets.count()


class TesterArtifactSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = TesterArtifact
        fields = ['id', 'file', 'file_url', 'description', 'uploaded_at']

    def get_file_url(self, obj):
        request = self.context.get('request')
        if obj.file and request:
            return request.build_absolute_uri(obj.file.url)
        return None


class VulnerabilityListSerializer(serializers.ModelSerializer):
    artifact_count = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'control_title', 'severity', 'category',
            'owasp', 'cve_id', 'cwe_id', 'created_at', 'artifact_count'
        ]

    def get_artifact_count(self, obj):
        return obj.artifacts.count()


class VulnerabilityDetailSerializer(serializers.ModelSerializer):
    artifacts = TesterArtifactSerializer(many=True, read_only=True)
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    asset_type = serializers.CharField(source='asset.asset_type', read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'asset', 'asset_name', 'asset_type',
            'control_title', 'control_description', 'control_impact',
            'control_recommendation', 'severity', 'affected_devices',
            'category', 'owasp', 'cve_id', 'cwe_id',
            'artifacts', 'created_at', 'updated_at'
        ]


class AssetListSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.SerializerMethodField()
    critical_count = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = [
            'id', 'name', 'asset_type', 'description',
            'technology_stack', 'vulnerability_count',
            'critical_count', 'created_at'
        ]

    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count()

    def get_critical_count(self, obj):
        return obj.vulnerabilities.filter(severity='critical').count()


class AssetDetailSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilityListSerializer(many=True, read_only=True)
    organization_name = serializers.CharField(source='organization.name', read_only=True)

    class Meta:
        model = Asset
        fields = [
            'id', 'organization', 'organization_name', 'name',
            'asset_type', 'description', 'technology_stack',
            'os_version', 'framework_version', 'ip_address',
            'url', 'internal_hostname', 'vulnerabilities',
            'created_at', 'updated_at'
        ]


class AIRemediationSerializer(serializers.ModelSerializer):
    vulnerability_title = serializers.CharField(source='vulnerability.control_title', read_only=True)

    class Meta:
        model = AIRemediation
        fields = [
            'id', 'vulnerability', 'vulnerability_title',
            'remediation_steps', 'model_used', 'is_helpful',
            'user_feedback', 'created_at', 'regeneration_count'
        ]
        read_only_fields = ['remediation_steps', 'model_used', 'created_at']


class RemediationFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemediationFeedback
        fields = [
            'id', 'remediation', 'was_helpful', 'comments',
            'user_steps', 'created_at'
        ]
        read_only_fields = ['stored_in_vector_db', 'vector_db_id']


class GenerateRemediationSerializer(serializers.Serializer):
    vulnerability_id = serializers.UUIDField()
    regenerate = serializers.BooleanField(default=False)


class SubmitFeedbackSerializer(serializers.Serializer):
    remediation_id = serializers.UUIDField()
    was_helpful = serializers.BooleanField()
    comments = serializers.CharField(required=False, allow_blank=True)
    user_steps = serializers.CharField(required=False, allow_blank=True)


class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ['id', 'role', 'content', 'created_at']
        read_only_fields = ['id', 'created_at']


class RemediationChatSerializer(serializers.ModelSerializer):
    messages = ChatMessageSerializer(many=True, read_only=True)
    message_count = serializers.SerializerMethodField()
    vulnerability_title = serializers.CharField(
        source='remediation.vulnerability.control_title',
        read_only=True
    )

    class Meta:
        model = RemediationChat
        fields = [
            'id', 'remediation', 'vulnerability_title', 'session_id',
            'is_active', 'message_count', 'messages',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'session_id', 'created_at', 'updated_at']

    def get_message_count(self, obj):
        return obj.messages.count()


class SendChatMessageSerializer(serializers.Serializer):
    remediation_id = serializers.UUIDField()
    message = serializers.CharField()
    chat_session_id = serializers.UUIDField(required=False)


class UpdateRemediationFromChatSerializer(serializers.Serializer):
    chat_session_id = serializers.UUIDField()
    update_reason = serializers.CharField(required=False, default="Based on chat clarifications")


class RemediationUpdateSerializer(serializers.ModelSerializer):
    vulnerability_title = serializers.CharField(
        source='remediation.vulnerability.control_title',
        read_only=True
    )

    class Meta:
        model = RemediationUpdate
        fields = [
            'id', 'remediation', 'vulnerability_title', 'chat_session',
            'previous_steps', 'updated_steps', 'update_reason', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class ChatMessageWithContextSerializer(serializers.ModelSerializer):
    """Serializer that includes full context about the chat message"""
    vulnerability_title = serializers.CharField(
        source='chat_session.remediation.vulnerability.control_title',
        read_only=True
    )
    vulnerability_id = serializers.UUIDField(
        source='chat_session.remediation.vulnerability.id',
        read_only=True
    )
    remediation_id = serializers.UUIDField(
        source='chat_session.remediation.id',
        read_only=True
    )
    asset_name = serializers.CharField(
        source='chat_session.remediation.vulnerability.asset.name',
        read_only=True
    )
    session_id = serializers.UUIDField(
        source='chat_session.id',
        read_only=True
    )
    
    class Meta:
        model = ChatMessage
        fields = [
            'id', 'session_id', 'remediation_id', 'vulnerability_id',
            'vulnerability_title', 'asset_name', 'role', 'content', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class RemediationChatDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer with full vulnerability and remediation context"""
    messages = ChatMessageSerializer(many=True, read_only=True)
    message_count = serializers.SerializerMethodField()
    
    # Vulnerability details
    vulnerability_id = serializers.UUIDField(source='remediation.vulnerability.id', read_only=True)
    vulnerability_title = serializers.CharField(source='remediation.vulnerability.control_title', read_only=True)
    vulnerability_severity = serializers.CharField(source='remediation.vulnerability.severity', read_only=True)
    vulnerability_category = serializers.CharField(source='remediation.vulnerability.category', read_only=True)
    
    # Asset details
    asset_id = serializers.UUIDField(source='remediation.vulnerability.asset.id', read_only=True)
    asset_name = serializers.CharField(source='remediation.vulnerability.asset.name', read_only=True)
    asset_type = serializers.CharField(source='remediation.vulnerability.asset.asset_type', read_only=True)
    
    # Remediation details
    remediation_id = serializers.UUIDField(source='remediation.id', read_only=True)
    current_remediation_steps = serializers.CharField(source='remediation.remediation_steps', read_only=True)
    
    # Update information
    has_updates = serializers.SerializerMethodField()
    update_count = serializers.SerializerMethodField()

    class Meta:
        model = RemediationChat
        fields = [
            'id', 'session_id', 'is_active', 'created_at', 'updated_at',
            'remediation_id', 'current_remediation_steps',
            'vulnerability_id', 'vulnerability_title', 'vulnerability_severity', 'vulnerability_category',
            'asset_id', 'asset_name', 'asset_type',
            'message_count', 'messages',
            'has_updates', 'update_count'
        ]

    def get_message_count(self, obj):
        return obj.messages.count()
    
    def get_has_updates(self, obj):
        return RemediationUpdate.objects.filter(chat_session=obj).exists()
    
    def get_update_count(self, obj):
        return RemediationUpdate.objects.filter(chat_session=obj).count()


class VulnerabilityRiskAssessmentSerializer(serializers.ModelSerializer):
    vulnerability_title = serializers.CharField(
        source='vulnerability.control_title', 
        read_only=True
    )
    vulnerability_severity = serializers.CharField(
        source='vulnerability.severity', 
        read_only=True
    )
    asset_name = serializers.CharField(
        source='vulnerability.asset.name', 
        read_only=True
    )
    
    class Meta:
        model = VulnerabilityRiskAssessment
        fields = [
            'id', 'vulnerability', 'vulnerability_title', 'vulnerability_severity',
            'asset_name', 'risk_score', 'risk_level', 'priority',
            'reasoning', 'key_risk_factors', 'recommended_timeline',
            'model_used', 'calculated_at', 'last_updated',
            'is_overridden', 'override_reason', 'overridden_by', 'overridden_at'
        ]
        read_only_fields = [
            'id', 'model_used', 'calculated_at', 'last_updated'
        ]


class AssetRiskAssessmentSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    asset_type = serializers.CharField(source='asset.asset_type', read_only=True)
    organization_name = serializers.CharField(
        source='asset.organization.name', 
        read_only=True
    )
    
    class Meta:
        model = AssetRiskAssessment
        fields = [
            'id', 'asset', 'asset_name', 'asset_type', 'organization_name',
            'risk_score', 'risk_level', 'priority',
            'reasoning', 'key_risk_factors', 'remediation_priority',
            'estimated_remediation_effort', 'vulnerability_summary',
            'model_used', 'calculated_at', 'last_updated',
            'is_overridden', 'override_reason', 'overridden_by', 'overridden_at'
        ]
        read_only_fields = [
            'id', 'model_used', 'calculated_at', 'last_updated'
        ]


class OrganizationRiskAssessmentSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(
        source='organization.name', 
        read_only=True
    )
    
    class Meta:
        model = OrganizationRiskAssessment
        fields = [
            'id', 'organization', 'organization_name',
            'risk_score', 'risk_level', 'priority',
            'reasoning', 'key_risk_factors', 'strategic_recommendations',
            'focus_areas', 'asset_summary',
            'model_used', 'calculated_at', 'last_updated',
            'is_overridden', 'override_reason', 'overridden_by', 'overridden_at'
        ]
        read_only_fields = [
            'id', 'model_used', 'calculated_at', 'last_updated'
        ]


class RiskAssessmentHistorySerializer(serializers.ModelSerializer):
    risk_score_change = serializers.SerializerMethodField()
    
    class Meta:
        model = RiskAssessmentHistory
        fields = [
            'id', 'assessment_type', 'object_id', 'object_name',
            'previous_risk_score', 'new_risk_score', 'risk_score_change',
            'previous_risk_level', 'new_risk_level',
            'change_reason', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_risk_score_change(self, obj):
        if obj.previous_risk_score is not None:
            return obj.new_risk_score - obj.previous_risk_score
        return obj.new_risk_score


# Enhanced serializers with risk assessment included

class VulnerabilityWithRiskSerializer(VulnerabilityDetailSerializer):
    """Vulnerability serializer with risk assessment"""
    risk_assessment = VulnerabilityRiskAssessmentSerializer(read_only=True)
    
    class Meta(VulnerabilityDetailSerializer.Meta):
        fields = VulnerabilityDetailSerializer.Meta.fields + ['risk_assessment']


class AssetWithRiskSerializer(AssetDetailSerializer):
    """Asset serializer with risk assessment"""
    risk_assessment = AssetRiskAssessmentSerializer(read_only=True)
    
    class Meta(AssetDetailSerializer.Meta):
        fields = AssetDetailSerializer.Meta.fields + ['risk_assessment']


class OrganizationWithRiskSerializer(OrganizationSerializer):
    """Organization serializer with risk assessment"""
    risk_assessment = OrganizationRiskAssessmentSerializer(read_only=True)
    
    class Meta(OrganizationSerializer.Meta):
        fields = OrganizationSerializer.Meta.fields + ['risk_assessment']


# Request serializers for risk calculation

class CalculateVulnerabilityRiskSerializer(serializers.Serializer):
    vulnerability_id = serializers.UUIDField()
    recalculate = serializers.BooleanField(default=False)


class CalculateAssetRiskSerializer(serializers.Serializer):
    asset_id = serializers.UUIDField()
    recalculate = serializers.BooleanField(default=False)


class CalculateOrganizationRiskSerializer(serializers.Serializer):
    organization_id = serializers.UUIDField()
    recalculate = serializers.BooleanField(default=False)


class OverrideRiskAssessmentSerializer(serializers.Serializer):
    assessment_id = serializers.UUIDField()
    assessment_type = serializers.ChoiceField(
        choices=['vulnerability', 'asset', 'organization']
    )
    new_risk_score = serializers.IntegerField(min_value=0, max_value=100)
    new_risk_level = serializers.ChoiceField(
        choices=['critical', 'high', 'medium', 'low', 'informational', 'none']
    )
    override_reason = serializers.CharField()
    overridden_by = serializers.CharField()


class BulkRiskCalculationSerializer(serializers.Serializer):
    """For bulk risk calculation operations"""
    scope = serializers.ChoiceField(
        choices=['all_vulnerabilities', 'all_assets', 'all_organizations', 
                 'organization', 'asset']
    )
    object_id = serializers.UUIDField(required=False)
    recalculate_existing = serializers.BooleanField(default=False)