from django.db import models
from django.core.validators import URLValidator
import uuid

class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Asset(models.Model):
    ASSET_TYPE_CHOICES = [
        ('application', 'Application'),
        ('server', 'Server'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='assets')
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPE_CHOICES)
    description = models.TextField(blank=True)
    
    # Technical details (sanitized for AI)
    technology_stack = models.TextField(blank=True, help_text="Technologies used (e.g., Python, Django, PostgreSQL)")
    os_version = models.CharField(max_length=100, blank=True)
    framework_version = models.CharField(max_length=100, blank=True)
    
    # Sensitive fields - NOT sent to AI
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    url = models.URLField(max_length=500, null=True, blank=True)
    internal_hostname = models.CharField(max_length=255, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.asset_type})"

    def get_sanitized_details(self):
        """Returns asset details safe for AI processing"""
        return {
            'name': self.name,
            'asset_type': self.asset_type,
            'description': self.description,
            'technology_stack': self.technology_stack,
            'os_version': self.os_version,
            'framework_version': self.framework_version,
        }


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('informational', 'Informational'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='vulnerabilities')
    
    control_title = models.CharField(max_length=500)
    control_description = models.TextField()
    control_impact = models.TextField()
    control_recommendation = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    
    affected_devices = models.TextField(help_text="Comma-separated list or description")
    category = models.CharField(max_length=100)
    owasp = models.CharField(max_length=100, blank=True, help_text="OWASP Classification")
    cve_id = models.CharField(max_length=50, blank=True, help_text="CVE ID if applicable")
    cwe_id = models.CharField(max_length=50, blank=True, help_text="CWE ID if applicable")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-severity', '-created_at']

    def __str__(self):
        return f"{self.control_title} - {self.severity}"


class TesterArtifact(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='artifacts')
    file = models.FileField(upload_to='tester_artifacts/%Y/%m/%d/')
    description = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Artifact for {self.vulnerability.control_title}"


class AIRemediation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='remediations')
    
    prompt_used = models.TextField()
    remediation_steps = models.TextField()
    model_used = models.CharField(max_length=50, default='gpt-4o-mini')
    
    is_helpful = models.BooleanField(null=True, blank=True)
    user_feedback = models.TextField(blank=True)
    user_provided_steps = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    regeneration_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Remediation for {self.vulnerability.control_title}"


class RemediationFeedback(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remediation = models.ForeignKey(AIRemediation, on_delete=models.CASCADE, related_name='feedback_entries')
    
    was_helpful = models.BooleanField()
    comments = models.TextField(blank=True)
    user_steps = models.TextField(blank=True, help_text="User-provided correct steps")
    
    stored_in_vector_db = models.BooleanField(default=False)
    vector_db_id = models.CharField(max_length=255, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback for {self.remediation.id} - {'Helpful' if self.was_helpful else 'Not Helpful'}"
    

class RemediationChat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remediation = models.ForeignKey(AIRemediation, on_delete=models.CASCADE, related_name='chat_sessions')
    session_id = models.UUIDField(default=uuid.uuid4, editable=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Chat for {self.remediation.vulnerability.control_title}"


class ChatMessage(models.Model):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('system', 'System'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    chat_session = models.ForeignKey(RemediationChat, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."


class RemediationUpdate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remediation = models.ForeignKey(AIRemediation, on_delete=models.CASCADE, related_name='updates')
    chat_session = models.ForeignKey(RemediationChat, on_delete=models.SET_NULL, null=True, blank=True)
    previous_steps = models.TextField()
    updated_steps = models.TextField()
    update_reason = models.TextField(help_text="Why was this update made")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Update for {self.remediation.id} at {self.created_at}"
    

class VulnerabilityRiskAssessment(models.Model):
    """Risk assessment for individual vulnerabilities"""
    RISK_LEVEL_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('informational', 'Informational'),
    ]
    
    PRIORITY_CHOICES = [
        ('p1_immediate', 'P1 - Immediate (Fix within 24h)'),
        ('p2_urgent', 'P2 - Urgent (Fix within 7 days)'),
        ('p3_high', 'P3 - High (Fix within 30 days)'),
        ('p4_medium', 'P4 - Medium (Fix within 90 days)'),
        ('p5_low', 'P5 - Low (Fix when possible)'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.OneToOneField(
        'Vulnerability', 
        on_delete=models.CASCADE, 
        related_name='risk_assessment'
    )
    
    # Risk metrics
    risk_score = models.IntegerField(
        help_text="AI-calculated risk score (0-100)"
    )
    risk_level = models.CharField(
        max_length=20, 
        choices=RISK_LEVEL_CHOICES
    )
    priority = models.CharField(
        max_length=20, 
        choices=PRIORITY_CHOICES
    )
    
    # AI reasoning
    reasoning = models.TextField(
        help_text="AI-generated explanation for the risk score"
    )
    key_risk_factors = models.JSONField(
        default=list,
        help_text="List of key factors contributing to risk"
    )
    recommended_timeline = models.CharField(
        max_length=100,
        help_text="AI-recommended remediation timeline"
    )
    
    # Metadata
    model_used = models.CharField(max_length=50, default='gpt-4o-mini')
    calculated_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Manual override capability
    is_overridden = models.BooleanField(default=False)
    override_reason = models.TextField(blank=True)
    overridden_by = models.CharField(max_length=255, blank=True)
    overridden_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-risk_score', '-calculated_at']
        verbose_name = "Vulnerability Risk Assessment"
        verbose_name_plural = "Vulnerability Risk Assessments"

    def __str__(self):
        return f"Risk: {self.risk_score} - {self.vulnerability.control_title}"


class AssetRiskAssessment(models.Model):
    """Aggregated risk assessment for assets"""
    RISK_LEVEL_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None'),
    ]
    
    PRIORITY_CHOICES = [
        ('p1_immediate', 'P1 - Immediate'),
        ('p2_urgent', 'P2 - Urgent'),
        ('p3_high', 'P3 - High'),
        ('p4_medium', 'P4 - Medium'),
        ('p5_low', 'P5 - Low'),
        ('none', 'None'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.OneToOneField(
        'Asset', 
        on_delete=models.CASCADE, 
        related_name='risk_assessment'
    )
    
    # Risk metrics
    risk_score = models.IntegerField(
        help_text="AI-calculated asset risk score (0-100)"
    )
    risk_level = models.CharField(
        max_length=20, 
        choices=RISK_LEVEL_CHOICES
    )
    priority = models.CharField(
        max_length=20, 
        choices=PRIORITY_CHOICES
    )
    
    # AI reasoning
    reasoning = models.TextField(
        help_text="AI-generated explanation for the asset risk"
    )
    key_risk_factors = models.JSONField(
        default=list,
        help_text="List of key risk factors for this asset"
    )
    remediation_priority = models.JSONField(
        default=list,
        help_text="AI-recommended priority order for fixing vulnerabilities"
    )
    estimated_remediation_effort = models.TextField(
        blank=True,
        help_text="Estimated effort to secure this asset"
    )
    
    # Vulnerability summary
    vulnerability_summary = models.JSONField(
        default=dict,
        help_text="Summary of vulnerabilities by severity"
    )
    
    # Metadata
    model_used = models.CharField(max_length=50, default='gpt-4o-mini')
    calculated_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Manual override
    is_overridden = models.BooleanField(default=False)
    override_reason = models.TextField(blank=True)
    overridden_by = models.CharField(max_length=255, blank=True)
    overridden_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-risk_score', '-calculated_at']
        verbose_name = "Asset Risk Assessment"
        verbose_name_plural = "Asset Risk Assessments"

    def __str__(self):
        return f"Risk: {self.risk_score} - {self.asset.name}"


class OrganizationRiskAssessment(models.Model):
    """Organization-wide risk assessment"""
    RISK_LEVEL_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(
        'Organization', 
        on_delete=models.CASCADE, 
        related_name='risk_assessment'
    )
    
    # Risk metrics
    risk_score = models.IntegerField(
        help_text="AI-calculated organization risk score (0-100)"
    )
    risk_level = models.CharField(
        max_length=20, 
        choices=RISK_LEVEL_CHOICES
    )
    priority = models.CharField(
        max_length=100,
        help_text="Strategic priority assessment"
    )
    
    # AI reasoning
    reasoning = models.TextField(
        help_text="AI-generated explanation for organization risk"
    )
    key_risk_factors = models.JSONField(
        default=list,
        help_text="List of organizational risk factors"
    )
    strategic_recommendations = models.JSONField(
        default=list,
        help_text="High-level strategic recommendations"
    )
    focus_areas = models.JSONField(
        default=list,
        help_text="Areas requiring immediate organizational focus"
    )
    
    # Summary statistics
    asset_summary = models.JSONField(
        default=dict,
        help_text="Summary of assets and vulnerabilities"
    )
    
    # Metadata
    model_used = models.CharField(max_length=50, default='gpt-4o-mini')
    calculated_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Manual override
    is_overridden = models.BooleanField(default=False)
    override_reason = models.TextField(blank=True)
    overridden_by = models.CharField(max_length=255, blank=True)
    overridden_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-risk_score', '-calculated_at']
        verbose_name = "Organization Risk Assessment"
        verbose_name_plural = "Organization Risk Assessments"

    def __str__(self):
        return f"Risk: {self.risk_score} - {self.organization.name}"


class RiskAssessmentHistory(models.Model):
    """Track historical changes in risk assessments"""
    ASSESSMENT_TYPE_CHOICES = [
        ('vulnerability', 'Vulnerability'),
        ('asset', 'Asset'),
        ('organization', 'Organization'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment_type = models.CharField(max_length=20, choices=ASSESSMENT_TYPE_CHOICES)
    
    # Generic foreign keys (store the ID as UUID)
    object_id = models.UUIDField()
    object_name = models.CharField(max_length=500, help_text="Name of the assessed object")
    
    # Historical data
    previous_risk_score = models.IntegerField(null=True, blank=True)
    new_risk_score = models.IntegerField()
    previous_risk_level = models.CharField(max_length=20, blank=True)
    new_risk_level = models.CharField(max_length=20)
    
    change_reason = models.TextField(
        blank=True,
        help_text="Why did the risk score change?"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Risk Assessment History"
        verbose_name_plural = "Risk Assessment History"
        indexes = [
            models.Index(fields=['assessment_type', 'object_id']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.assessment_type} - {self.object_name}: {self.previous_risk_score} → {self.new_risk_score}"