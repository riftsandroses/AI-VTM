"""
Risk Scoring Service - AI-powered vulnerability risk assessment
"""
from django.conf import settings
from openai import OpenAI
import json
from decimal import Decimal
from .models import Vulnerability
from django.db.models import Count, Avg, Q

client = OpenAI(api_key=settings.OPENAI_API_KEY)


class RiskScoringService:
    """Service for AI-powered risk scoring and prioritization"""
    
    def __init__(self):
        self.model = "gpt-4o-mini"
    
    def calculate_vulnerability_risk(self, vulnerability):
        """
        Calculate comprehensive risk score for a vulnerability
        Returns: dict with risk_score (0-100), risk_level, priority, and reasoning
        """
        asset = vulnerability.asset
        organization = asset.organization
        
        # Prepare context
        context = self._prepare_vulnerability_context(vulnerability, asset, organization)
        
        # Build prompt
        prompt = self._build_vulnerability_risk_prompt(context)
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity risk assessment expert. 
                        Analyze vulnerabilities and provide risk scores based on:
                        - Severity and exploitability
                        - Asset criticality and exposure
                        - Business impact
                        - Threat landscape
                        - Organizational context
                        
                        Respond ONLY with valid JSON, no markdown formatting."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Validate and normalize response
            return self._normalize_risk_response(result, 'vulnerability')
            
        except Exception as e:
            raise Exception(f"Failed to calculate vulnerability risk: {str(e)}")
    
    def calculate_asset_risk(self, asset):
        """
        Calculate aggregated risk score for an asset based on all its vulnerabilities
        Returns: dict with risk_score, risk_level, priority, and reasoning
        """
        vulnerabilities = asset.vulnerabilities.all()
        
        if not vulnerabilities.exists():
            return {
                'risk_score': 0,
                'risk_level': 'none',
                'priority': 'none',
                'reasoning': 'No vulnerabilities found for this asset.',
                'vulnerability_summary': {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            }
        
        # Get vulnerability statistics
        vuln_stats = self._get_vulnerability_statistics(vulnerabilities)
        
        # Get individual risk scores if available
        vuln_risks = []
        for vuln in vulnerabilities:
            if hasattr(vuln, 'risk_assessment') and vuln.risk_assessment:
                vuln_risks.append({
                    'title': vuln.control_title,
                    'severity': vuln.severity,
                    'risk_score': vuln.risk_assessment.risk_score,
                    'category': vuln.category
                })
        
        context = self._prepare_asset_context(asset, vuln_stats, vuln_risks)
        prompt = self._build_asset_risk_prompt(context)
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity risk assessment expert.
                        Analyze asset-level risk considering all vulnerabilities and context.
                        Respond ONLY with valid JSON, no markdown formatting."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1200,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            result['vulnerability_summary'] = vuln_stats
            
            return self._normalize_risk_response(result, 'asset')
            
        except Exception as e:
            raise Exception(f"Failed to calculate asset risk: {str(e)}")
    
    def calculate_organization_risk(self, organization):
        """
        Calculate organization-wide risk score
        Returns: dict with risk_score, risk_level, priority, and reasoning
        """
        assets = organization.assets.all()
        
        if not assets.exists():
            return {
                'risk_score': 0,
                'risk_level': 'none',
                'priority': 'none',
                'reasoning': 'No assets found for this organization.',
                'asset_summary': {
                    'total_assets': 0,
                    'total_vulnerabilities': 0
                }
            }
        
        # Get organization-wide statistics
        org_stats = self._get_organization_statistics(organization)
        
        # Get asset risk scores if available
        asset_risks = []
        for asset in assets:
            if hasattr(asset, 'risk_assessment') and asset.risk_assessment:
                asset_risks.append({
                    'name': asset.name,
                    'type': asset.asset_type,
                    'risk_score': asset.risk_assessment.risk_score,
                    'vulnerability_count': asset.vulnerabilities.count()
                })
        
        context = self._prepare_organization_context(organization, org_stats, asset_risks)
        prompt = self._build_organization_risk_prompt(context)
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity risk assessment expert.
                        Analyze organization-wide security posture and risk.
                        Respond ONLY with valid JSON, no markdown formatting."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            result['asset_summary'] = org_stats
            
            return self._normalize_risk_response(result, 'organization')
            
        except Exception as e:
            raise Exception(f"Failed to calculate organization risk: {str(e)}")
    
    def _prepare_vulnerability_context(self, vulnerability, asset, organization):
        """Prepare context for vulnerability risk assessment"""
        return {
            'vulnerability': {
                'title': vulnerability.control_title,
                'description': vulnerability.control_description,
                'impact': vulnerability.control_impact,
                'severity': vulnerability.severity,
                'category': vulnerability.category,
                'owasp': vulnerability.owasp,
                'cve_id': vulnerability.cve_id,
                'cwe_id': vulnerability.cwe_id,
                'affected_devices': vulnerability.affected_devices
            },
            'asset': {
                'name': asset.name,
                'type': asset.asset_type,
                'technology_stack': asset.technology_stack,
                'os_version': asset.os_version,
                'framework_version': asset.framework_version,
                'has_public_exposure': bool(asset.url),
                'description': asset.description
            },
            'organization': {
                'name': organization.name,
                'description': organization.description,
                'asset_count': organization.assets.count()
            }
        }
    
    def _prepare_asset_context(self, asset, vuln_stats, vuln_risks):
        """Prepare context for asset risk assessment"""
        return {
            'asset': {
                'name': asset.name,
                'type': asset.asset_type,
                'description': asset.description,
                'technology_stack': asset.technology_stack,
                'os_version': asset.os_version,
                'framework_version': asset.framework_version,
                'has_public_exposure': bool(asset.url)
            },
            'organization': {
                'name': asset.organization.name,
                'description': asset.organization.description
            },
            'vulnerability_statistics': vuln_stats,
            'vulnerability_risks': vuln_risks[:10]  # Top 10 for context
        }
    
    def _prepare_organization_context(self, organization, org_stats, asset_risks):
        """Prepare context for organization risk assessment"""
        return {
            'organization': {
                'name': organization.name,
                'description': organization.description
            },
            'statistics': org_stats,
            'asset_risks': asset_risks[:20]  # Top 20 assets
        }
    
    def _build_vulnerability_risk_prompt(self, context):
        """Build prompt for vulnerability risk assessment"""
        return f"""Analyze this vulnerability and provide a comprehensive risk assessment.

VULNERABILITY DETAILS:
Title: {context['vulnerability']['title']}
Description: {context['vulnerability']['description']}
Impact: {context['vulnerability']['impact']}
Severity: {context['vulnerability']['severity']}
Category: {context['vulnerability']['category']}
OWASP: {context['vulnerability'].get('owasp', 'N/A')}
CVE: {context['vulnerability'].get('cve_id', 'N/A')}
CWE: {context['vulnerability'].get('cwe_id', 'N/A')}

ASSET CONTEXT:
Name: {context['asset']['name']}
Type: {context['asset']['type']}
Technology: {context['asset'].get('technology_stack', 'Not specified')}
Public Exposure: {'Yes' if context['asset']['has_public_exposure'] else 'No'}

ORGANIZATION CONTEXT:
Name: {context['organization']['name']}
Total Assets: {context['organization']['asset_count']}

Provide a risk assessment with:
1. risk_score: Integer 0-100 (0=no risk, 100=critical risk)
2. risk_level: One of ["critical", "high", "medium", "low", "informational"]
3. priority: One of ["p1_immediate", "p2_urgent", "p3_high", "p4_medium", "p5_low"]
4. reasoning: Detailed explanation (2-3 paragraphs) of:
   - Why this score was assigned
   - Key risk factors considered
   - Business impact assessment
   - Exploitability and threat landscape
5. key_risk_factors: Array of 3-5 specific factors
6. recommended_timeline: When to remediate (e.g., "Within 24 hours", "Within 7 days")

Return as JSON with these exact keys."""
    
    def _build_asset_risk_prompt(self, context):
        """Build prompt for asset risk assessment"""
        vuln_summary = context['vulnerability_statistics']
        
        return f"""Analyze this asset's overall security risk based on its vulnerabilities.

ASSET DETAILS:
Name: {context['asset']['name']}
Type: {context['asset']['type']}
Description: {context['asset'].get('description', 'N/A')}
Technology: {context['asset'].get('technology_stack', 'Not specified')}
Public Exposure: {'Yes' if context['asset']['has_public_exposure'] else 'No'}

VULNERABILITY SUMMARY:
Total Vulnerabilities: {vuln_summary['total']}
Critical: {vuln_summary['critical']}
High: {vuln_summary['high']}
Medium: {vuln_summary['medium']}
Low: {vuln_summary['low']}
Informational: {vuln_summary['informational']}

Top Vulnerability Categories:
{json.dumps(vuln_summary.get('top_categories', []), indent=2)}

Individual Vulnerability Risks:
{json.dumps(context['vulnerability_risks'], indent=2)}

ORGANIZATION: {context['organization']['name']}

Provide an asset-level risk assessment with:
1. risk_score: Integer 0-100
2. risk_level: One of ["critical", "high", "medium", "low", "none"]
3. priority: One of ["p1_immediate", "p2_urgent", "p3_high", "p4_medium", "p5_low"]
4. reasoning: Detailed explanation covering:
   - Overall security posture
   - Most concerning vulnerabilities
   - Attack surface analysis
   - Business criticality
5. key_risk_factors: Array of 3-5 factors
6. remediation_priority: Array of top 3-5 vulnerabilities to fix first
7. estimated_remediation_effort: Overall effort estimate

Return as JSON with these exact keys."""
    
    def _build_organization_risk_prompt(self, context):
        """Build prompt for organization risk assessment"""
        stats = context['statistics']
        
        return f"""Analyze this organization's overall cybersecurity risk posture.

ORGANIZATION: {context['organization']['name']}
Description: {context['organization'].get('description', 'N/A')}

OVERALL STATISTICS:
Total Assets: {stats['total_assets']}
Total Vulnerabilities: {stats['total_vulnerabilities']}

Vulnerability Distribution:
Critical: {stats['vulnerability_breakdown']['critical']}
High: {stats['vulnerability_breakdown']['high']}
Medium: {stats['vulnerability_breakdown']['medium']}
Low: {stats['vulnerability_breakdown']['low']}

Asset Type Distribution:
{json.dumps(stats['asset_type_distribution'], indent=2)}

Assets with Public Exposure: {stats['public_exposure_count']}

Top Vulnerability Categories:
{json.dumps(stats['top_vulnerability_categories'], indent=2)}

Individual Asset Risks:
{json.dumps(context['asset_risks'], indent=2)}

Provide an organization-level risk assessment with:
1. risk_score: Integer 0-100
2. risk_level: One of ["critical", "high", "medium", "low", "none"]
3. priority: Strategic priority level
4. reasoning: Comprehensive analysis covering:
   - Overall security maturity
   - Systemic risks and patterns
   - Critical assets and exposure
   - Organizational risk tolerance
5. key_risk_factors: Array of 5-7 organizational risk factors
6. strategic_recommendations: Array of 3-5 high-level recommendations
7. focus_areas: Array of areas needing immediate attention

Return as JSON with these exact keys."""
    
    def _get_vulnerability_statistics(self, vulnerabilities):
        """Get statistics from vulnerability queryset"""
        stats = vulnerabilities.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low')),
            informational=Count('id', filter=Q(severity='informational'))
        )
        
        # Get top categories
        categories = vulnerabilities.values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        stats['top_categories'] = [
            {'category': cat['category'], 'count': cat['count']}
            for cat in categories
        ]
        
        return stats
    
    def _get_organization_statistics(self, organization):
        """Get organization-wide statistics"""
        
        assets = organization.assets.all()
        vulnerabilities = Vulnerability.objects.filter(asset__organization=organization)
        
        stats = {
            'total_assets': assets.count(),
            'total_vulnerabilities': vulnerabilities.count(),
            'vulnerability_breakdown': {
                'critical': vulnerabilities.filter(severity='critical').count(),
                'high': vulnerabilities.filter(severity='high').count(),
                'medium': vulnerabilities.filter(severity='medium').count(),
                'low': vulnerabilities.filter(severity='low').count(),
                'informational': vulnerabilities.filter(severity='informational').count()
            },
            'asset_type_distribution': {},
            'public_exposure_count': assets.filter(url__isnull=False).exclude(url='').count()
        }
        
        # Asset type distribution
        for asset_type in assets.values('asset_type').annotate(count=Count('id')):
            stats['asset_type_distribution'][asset_type['asset_type']] = asset_type['count']
        
        # Top vulnerability categories
        categories = vulnerabilities.values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        stats['top_vulnerability_categories'] = [
            {'category': cat['category'], 'count': cat['count']}
            for cat in categories
        ]
        
        return stats
    
    def _normalize_risk_response(self, result, level_type):
        """Normalize and validate AI response"""
        # Ensure risk_score is within bounds
        risk_score = min(100, max(0, int(result.get('risk_score', 50))))
        
        # Validate risk_level
        valid_risk_levels = ['critical', 'high', 'medium', 'low', 'informational', 'none']
        risk_level = result.get('risk_level', 'medium')
        if risk_level not in valid_risk_levels:
            risk_level = self._score_to_risk_level(risk_score)
        
        # Validate priority
        valid_priorities = ['p1_immediate', 'p2_urgent', 'p3_high', 'p4_medium', 'p5_low', 'none']
        priority = result.get('priority', 'p4_medium')
        if priority not in valid_priorities:
            priority = self._score_to_priority(risk_score)
        
        normalized = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'priority': priority,
            'reasoning': result.get('reasoning', 'Risk assessment completed.'),
            'key_risk_factors': result.get('key_risk_factors', []),
        }
        
        # Add level-specific fields
        if level_type == 'vulnerability':
            normalized['recommended_timeline'] = result.get('recommended_timeline', 'Within 30 days')
        elif level_type == 'asset':
            normalized['remediation_priority'] = result.get('remediation_priority', [])
            normalized['estimated_remediation_effort'] = result.get('estimated_remediation_effort', 'Unknown')
        elif level_type == 'organization':
            normalized['strategic_recommendations'] = result.get('strategic_recommendations', [])
            normalized['focus_areas'] = result.get('focus_areas', [])
        
        return normalized
    
    def _score_to_risk_level(self, score):
        """Convert numeric score to risk level"""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 10:
            return 'low'
        else:
            return 'informational'
    
    def _score_to_priority(self, score):
        """Convert numeric score to priority"""
        if score >= 90:
            return 'p1_immediate'
        elif score >= 75:
            return 'p2_urgent'
        elif score >= 50:
            return 'p3_high'
        elif score >= 25:
            return 'p4_medium'
        else:
            return 'p5_low'