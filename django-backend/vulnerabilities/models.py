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