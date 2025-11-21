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
    
    def process_feedback(self, remediation, was_helpful, comments="", user_steps=""):
        """Process user feedback on remediation"""
        vulnerability = remediation.vulnerability
        asset = vulnerability.asset
        
        if was_helpful:
            # Store in vector DB
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
            
            vector_id = self.vector_db.add_successful_remediation(
                vuln_data,
                asset_data,
                remediation.remediation_steps,
                user_steps if user_steps else None
            )
            
            return vector_id
        else:
            # If not helpful and user provided steps, store those
            if user_steps:
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
                
                vector_id = self.vector_db.add_successful_remediation(
                    vuln_data,
                    asset_data,
                    user_steps,  # Store user steps as the primary solution
                    None
                )
                
                return vector_id
        
        return None