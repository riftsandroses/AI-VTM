# serializers.py
from rest_framework import serializers
from .models import (
    Organization, Asset, Vulnerability, TesterArtifact,
    AIRemediation, RemediationFeedback
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