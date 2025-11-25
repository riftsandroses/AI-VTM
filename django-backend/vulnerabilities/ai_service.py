from django.conf import settings
import chromadb
from chromadb.config import Settings as ChromaSettings
import uuid
import json
import re
from openai import OpenAI
client = OpenAI(api_key=settings.OPENAI_API_KEY)


OpenAI.api_key = settings.OPENAI_API_KEY


class VectorDBManager:
    """Manages local ChromaDB for storing successful remediation patterns"""
    
    def __init__(self):
        self.client = chromadb.PersistentClient(
            path=settings.CHROMADB_PATH,
            settings=ChromaSettings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        self.collection = self.client.get_or_create_collection(
            name="remediation_patterns",
            metadata={"description": "Successful vulnerability remediation patterns"}
        )
        # Create collection for feedback patterns
        self.feedback_collection = self.client.get_or_create_collection(
            name="remediation_feedback",
            metadata={"description": "Feedback on remediations - what works and what doesn't"}
        )
        # Create collection for risk assessment insights
        self.risk_insights_collection = self.client.get_or_create_collection(
            name="risk_assessment_insights",
            metadata={"description": "Risk assessment overrides and adjustments"}
        )
    
    def add_successful_remediation(self, vulnerability_data, asset_data, remediation_steps, user_steps=None):
        """Store successful remediation in vector DB"""
        doc_id = str(uuid.uuid4())
        
        # Sanitize data - remove any IP/URL information
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        # Create document text
        document = f"""
Vulnerability: {sanitized_vuln.get('control_title', 'N/A')}
Category: {sanitized_vuln.get('category', 'N/A')}
Severity: {sanitized_vuln.get('severity', 'N/A')}
OWASP: {sanitized_vuln.get('owasp', 'N/A')}
CWE: {sanitized_vuln.get('cwe_id', 'N/A')}
CVE: {sanitized_vuln.get('cve_id', 'N/A')}

Description: {sanitized_vuln.get('control_description', 'N/A')}
Impact: {sanitized_vuln.get('control_impact', 'N/A')}

Asset Type: {sanitized_asset.get('asset_type', 'N/A')}
Technology Stack: {sanitized_asset.get('technology_stack', 'N/A')}
OS Version: {sanitized_asset.get('os_version', 'N/A')}
Framework: {sanitized_asset.get('framework_version', 'N/A')}

AI Generated Steps:
{remediation_steps}

{"User Provided Steps:" if user_steps else ""}
{user_steps if user_steps else ""}
        """.strip()
        
        metadata = {
            "vulnerability_title": sanitized_vuln.get('control_title', 'Unknown'),
            "category": sanitized_vuln.get('category', 'Unknown'),
            "severity": sanitized_vuln.get('severity', 'Unknown'),
            "asset_type": sanitized_asset.get('asset_type', 'Unknown'),
            "owasp": sanitized_vuln.get('owasp', ''),
            "cwe_id": sanitized_vuln.get('cwe_id', ''),
            "has_user_steps": bool(user_steps)
        }
        
        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        return doc_id
    
    # Store feedback patterns (positive and negative)
    def store_feedback_pattern(self, vulnerability_data, asset_data, remediation_steps, 
                               feedback_type, was_helpful, comments="", user_steps=""):
        """
        Store feedback patterns to guide future remediations
        
        Args:
            vulnerability_data: Vulnerability details
            asset_data: Asset details
            remediation_steps: Original AI-generated steps
            feedback_type: 'positive' or 'negative'
            was_helpful: Boolean
            comments: User comments
            user_steps: Alternative/corrected steps provided by user
        """
        doc_id = str(uuid.uuid4())
        
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        # Create detailed feedback document
        document = f"""
FEEDBACK TYPE: {feedback_type.upper()}
HELPFUL: {was_helpful}

Vulnerability: {sanitized_vuln.get('control_title', 'N/A')}
Category: {sanitized_vuln.get('category', 'N/A')}
Severity: {sanitized_vuln.get('severity', 'N/A')}
OWASP: {sanitized_vuln.get('owasp', 'N/A')}
CWE: {sanitized_vuln.get('cwe_id', 'N/A')}
CVE: {sanitized_vuln.get('cve_id', 'N/A')}

Description: {sanitized_vuln.get('control_description', 'N/A')}
Impact: {sanitized_vuln.get('control_impact', 'N/A')}

Asset Type: {sanitized_asset.get('asset_type', 'N/A')}
Technology Stack: {sanitized_asset.get('technology_stack', 'N/A')}
OS Version: {sanitized_asset.get('os_version', 'N/A')}

{"WHAT WORKED:" if was_helpful else "WHAT DIDN'T WORK:"}
{remediation_steps}

{"USER FEEDBACK:" if comments else ""}
{comments if comments else ""}

{"CORRECTED/IMPROVED STEPS:" if user_steps else ""}
{user_steps if user_steps else ""}

{"LESSONS LEARNED:" if was_helpful else "ISSUES TO AVOID:"}
{self._extract_lessons(feedback_type, remediation_steps, user_steps, comments)}
        """.strip()
        
        metadata = {
            "vulnerability_title": sanitized_vuln.get('control_title', 'Unknown'),
            "category": sanitized_vuln.get('category', 'Unknown'),
            "severity": sanitized_vuln.get('severity', 'Unknown'),
            "asset_type": sanitized_asset.get('asset_type', 'Unknown'),
            "feedback_type": feedback_type,
            "was_helpful": was_helpful,
            "owasp": sanitized_vuln.get('owasp', ''),
            "cwe_id": sanitized_vuln.get('cwe_id', ''),
            "has_user_correction": bool(user_steps),
            "has_comments": bool(comments)
        }
        
        self.feedback_collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        return doc_id
    
    # Store risk assessment overrides and insights
    def store_risk_assessment_update(self, vulnerability_data, asset_data, 
                                     previous_assessment, new_assessment, 
                                     action_type, reason=""):
        """
        Store risk assessment changes to inform future risk calculations
        
        Args:
            vulnerability_data: Vulnerability details
            asset_data: Asset details
            previous_assessment: Dict with previous risk metrics
            new_assessment: Dict with new risk metrics
            action_type: 'override' or 'revert'
            reason: Explanation for the change
        """
        doc_id = str(uuid.uuid4())
        
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        # Create risk update document
        document = f"""
RISK ASSESSMENT UPDATE: {action_type.upper()}

Vulnerability: {sanitized_vuln.get('control_title', 'N/A')}
Category: {sanitized_vuln.get('category', 'N/A')}
OWASP: {sanitized_vuln.get('owasp', 'N/A')}
CWE: {sanitized_vuln.get('cwe_id', 'N/A')}
CVE: {sanitized_vuln.get('cve_id', 'N/A')}

Description: {sanitized_vuln.get('control_description', 'N/A')}
Impact: {sanitized_vuln.get('control_impact', 'N/A')}

Asset: {sanitized_asset.get('asset_type', 'N/A')} - {sanitized_asset.get('name', 'N/A')}
Technology Stack: {sanitized_asset.get('technology_stack', 'N/A')}

PREVIOUS ASSESSMENT:
- Risk Score: {previous_assessment.get('risk_score', 'N/A')}
- Risk Level: {previous_assessment.get('risk_level', 'N/A')}
- Priority: {previous_assessment.get('priority', 'N/A')}
- Reasoning: {previous_assessment.get('reasoning', 'N/A')[:500]}

NEW ASSESSMENT:
- Risk Score: {new_assessment.get('risk_score', 'N/A')}
- Risk Level: {new_assessment.get('risk_level', 'N/A')}
- Priority: {new_assessment.get('priority', 'N/A')}
- Reasoning: {new_assessment.get('reasoning', 'N/A')[:500]}

CHANGE ANALYSIS:
Score Change: {new_assessment.get('risk_score', 0) - previous_assessment.get('risk_score', 0):+d}
Reason for Change:
{reason}

KEY FACTORS TO CONSIDER:
{json.dumps(new_assessment.get('key_risk_factors', []), indent=2)}
        """.strip()
        
        metadata = {
            "vulnerability_title": sanitized_vuln.get('control_title', 'Unknown'),
            "category": sanitized_vuln.get('category', 'Unknown'),
            "asset_type": sanitized_asset.get('asset_type', 'Unknown'),
            "action_type": action_type,
            "score_change": new_assessment.get('risk_score', 0) - previous_assessment.get('risk_score', 0),
            "level_change": f"{previous_assessment.get('risk_level', 'unknown')} -> {new_assessment.get('risk_level', 'unknown')}",
            "owasp": sanitized_vuln.get('owasp', ''),
            "cwe_id": sanitized_vuln.get('cwe_id', '')
        }
        
        self.risk_insights_collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        return doc_id
    
    # Search feedback patterns
    def search_feedback_patterns(self, vulnerability_data, asset_data, n_results=3):
        """Search for feedback on similar vulnerabilities"""
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        query = f"""
Feedback for {sanitized_vuln.get('control_title', '')} 
{sanitized_vuln.get('category', '')} 
{sanitized_vuln.get('owasp', '')}
{sanitized_asset.get('technology_stack', '')}
        """.strip()
        
        try:
            results = self.feedback_collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            if results and results['documents'] and results['documents'][0]:
                return results['documents'][0]
            return []
        except Exception as e:
            print(f"Feedback pattern search error: {e}")
            return []
        
    # Search risk assessment insights
    def search_risk_insights(self, vulnerability_data, asset_data, n_results=3):
        """Search for risk assessment patterns on similar vulnerabilities"""
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        query = f"""
Risk assessment insights for {sanitized_vuln.get('control_title', '')} 
{sanitized_vuln.get('category', '')} 
{sanitized_asset.get('asset_type', '')}
        """.strip()
        
        try:
            results = self.risk_insights_collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            if results and results['documents'] and results['documents'][0]:
                return results['documents'][0]
            return []
        except Exception as e:
            print(f"Risk insights search error: {e}")
            return []
    
    def _sanitize_data(self, data):
        """Remove sensitive information like IP addresses and URLs"""
        if isinstance(data, dict):
            sanitized = {}
            sensitive_fields = ['ip_address', 'url', 'internal_hostname', 'hostname']
            
            for key, value in data.items():
                if key in sensitive_fields:
                    continue
                
                if isinstance(value, str):
                    # Remove IP addresses
                    value = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', value)
                    # Remove URLs
                    value = re.sub(r'https?://[^\s]+', '[REDACTED_URL]', value)
                    value = re.sub(r'www\.[^\s]+', '[REDACTED_URL]', value)
                
                sanitized[key] = value
            
            return sanitized
        return data
    
    # Extract lessons from feedback
    def _extract_lessons(self, feedback_type, remediation_steps, user_steps, comments):
        """Extract key lessons from feedback"""
        lessons = []
        
        if feedback_type == 'positive':
            lessons.append("- This approach was validated and should be considered for similar cases")
            if user_steps:
                lessons.append("- User provided additional improvements worth capturing")
        else:
            lessons.append("- This approach should be avoided or refined for similar vulnerabilities")
            if user_steps:
                lessons.append("- User provided a corrected approach to follow")
            if "performance" in comments.lower():
                lessons.append("- Be mindful of performance implications")
            if "compatibility" in comments.lower():
                lessons.append("- Check compatibility with existing systems")
            if "security" in comments.lower():
                lessons.append("- Verify security implications before implementation")
        
        return "\n".join(lessons) if lessons else "No specific lessons extracted"
    
    def search_similar_remediations(self, vulnerability_data, asset_data, n_results=3):
        """Search for similar vulnerability remediations"""
        sanitized_asset = self._sanitize_data(asset_data)
        sanitized_vuln = self._sanitize_data(vulnerability_data)
        
        query = f"""
{sanitized_vuln.get('control_title', '')} 
{sanitized_vuln.get('category', '')} 
{sanitized_vuln.get('owasp', '')}
{sanitized_vuln.get('cwe_id', '')}
{sanitized_asset.get('technology_stack', '')}
        """.strip()
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            if results and results['documents'] and results['documents'][0]:
                return results['documents'][0]
            return []
        except Exception as e:
            print(f"Vector DB search error: {e}")
            return []


class AIRemediationService:
    """Service for generating AI-powered vulnerability remediations"""
    
    def __init__(self):
        self.model = "gpt-4o-mini"
        self.vector_db = VectorDBManager()
    
    def generate_remediation(self, vulnerability, regenerate=False):
        """Generate remediation steps for a vulnerability"""
        asset = vulnerability.asset
        
        # Get sanitized asset details (no IP/URL)
        asset_data = asset.get_sanitized_details()
        
        # Prepare vulnerability data
        vuln_data = {
            'control_title': vulnerability.control_title,
            'control_description': vulnerability.control_description,
            'control_impact': vulnerability.control_impact,
            'control_recommendation': vulnerability.control_recommendation,
            'severity': vulnerability.severity,
            'category': vulnerability.category,
            'owasp': vulnerability.owasp,
            'cve_id': vulnerability.cve_id,
            'cwe_id': vulnerability.cwe_id,
        }
        
        # Search for similar remediations
        similar_remediations = self.vector_db.search_similar_remediations(vuln_data, asset_data)
        
        # Build prompt
        prompt = self._build_prompt(vuln_data, asset_data, similar_remediations, regenerate)
        
        # Call OpenAI API
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert specializing in vulnerability remediation. "
                            "Provide clear, actionable, and specific steps to remediate vulnerabilities. "
                            "Focus on practical implementation details."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7 if regenerate else 0.3,
                max_tokens=2000
            )

            remediation_steps = response.choices[0].message.content.strip()
            return remediation_steps, prompt

        except Exception as e:
            raise Exception(f"Failed to generate remediation: {str(e)}")
        
    def process_feedback(self, remediation, was_helpful, comments="", user_steps=""):
        """
        Process user feedback on remediation
        
        Store both positive and negative feedback in Vector DB
        """
        vulnerability = remediation.vulnerability
        asset = vulnerability.asset
        
        vuln_data = {
            'control_title': vulnerability.control_title,
            'control_description': vulnerability.control_description,
            'control_impact': vulnerability.control_impact,
            'severity': vulnerability.severity,
            'category': vulnerability.category,
            'owasp': vulnerability.owasp,
            'cve_id': vulnerability.cve_id,
            'cwe_id': vulnerability.cwe_id,
        }
        
        asset_data = asset.get_sanitized_details()
        
        # Store feedback pattern (positive or negative)
        feedback_type = 'positive' if was_helpful else 'negative'
        vector_id = self.vector_db.store_feedback_pattern(
            vuln_data,
            asset_data,
            remediation.remediation_steps,
            feedback_type,
            was_helpful,
            comments,
            user_steps if user_steps else None
        )
        
        # Also store in traditional success collection if helpful
        if was_helpful:
            success_vector_id = self.vector_db.add_successful_remediation(
                vuln_data,
                asset_data,
                remediation.remediation_steps,
                user_steps if user_steps else None
            )
            return vector_id, success_vector_id
        
        return vector_id, None
    
    def _build_prompt(self, vuln_data, asset_data, similar_remediations, regenerate):
        """Build the prompt for OpenAI"""
        prompt_parts = [
            "# Vulnerability Remediation Request\n",
            "## Vulnerability Details",
            f"**Title:** {vuln_data['control_title']}",
            f"**Description:** {vuln_data['control_description']}",
            f"**Impact:** {vuln_data['control_impact']}",
            f"**Current Recommendation:** {vuln_data['control_recommendation']}",
            f"**Severity:** {vuln_data['severity']}",
            f"**Category:** {vuln_data['category']}",
        ]
        
        if vuln_data.get('owasp'):
            prompt_parts.append(f"**OWASP:** {vuln_data['owasp']}")
        if vuln_data.get('cve_id'):
            prompt_parts.append(f"**CVE ID:** {vuln_data['cve_id']}")
        if vuln_data.get('cwe_id'):
            prompt_parts.append(f"**CWE ID:** {vuln_data['cwe_id']}")
        
        prompt_parts.extend([
            "\n## Asset Context",
            f"**Asset Type:** {asset_data['asset_type']}",
            f"**Technology Stack:** {asset_data.get('technology_stack', 'Not specified')}",
            f"**OS Version:** {asset_data.get('os_version', 'Not specified')}",
            f"**Framework Version:** {asset_data.get('framework_version', 'Not specified')}",
        ])
        
        if similar_remediations:
            prompt_parts.append("\n## Similar Past Remediations")
            prompt_parts.append("Here are successful remediations for similar vulnerabilities:")
            for i, rem in enumerate(similar_remediations[:2], 1):
                prompt_parts.append(f"\n### Example {i}")
                prompt_parts.append(rem[:1000])  # Limit context length
        
        prompt_parts.extend([
            "\n## Requirements",
            "Provide detailed, step-by-step remediation instructions that:",
            "1. Are specific to the technology stack and environment described",
            "2. Include actual commands, code snippets, or configuration changes where applicable",
            "3. Consider the severity and impact of the vulnerability",
            "4. Include verification steps to confirm the fix",
            "5. Mention any potential side effects or testing requirements",
            "6. Are organized in a clear, numbered format",
            "\nProvide the remediation steps now:"
        ])
        
        if regenerate:
            prompt_parts.append("\nNOTE: This is a regeneration request. Provide an alternative approach or more detailed steps.")
        
        return "\n".join(prompt_parts)