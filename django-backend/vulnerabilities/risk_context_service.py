"""
Risk Context Service - Handle context-based risk recalculation
"""
from django.conf import settings
from openai import OpenAI
import json
from .models import (
    Vulnerability, Asset, Organization,
    VulnerabilityRiskAssessment, AssetRiskAssessment, OrganizationRiskAssessment,
    RiskContext, RiskContextChat, RiskContextChatMessage
)
from .risk_scoring_service import RiskScoringService

client = OpenAI(api_key=settings.OPENAI_API_KEY)


class RiskContextService:
    """Service for handling risk context additions and similar vulnerability detection"""
    
    def __init__(self):
        self.model = "gpt-4o-mini"
        self.risk_service = RiskScoringService()
    
    def add_context_and_recalculate(self, context_type, object_id, context_text, added_by):
        """
        Add context to a risk assessment and recalculate
        
        Args:
            context_type: 'vulnerability', 'asset', or 'organization'
            object_id: UUID of the object
            context_text: Additional context provided by user
            added_by: User who added the context
            
        Returns:
            dict with new risk assessment and context record
        """
        # Get the object and its current assessment
        if context_type == 'vulnerability':
            obj = Vulnerability.objects.get(id=object_id)
            current_assessment = VulnerabilityRiskAssessment.objects.filter(
                vulnerability=obj
            ).first()
        elif context_type == 'asset':
            obj = Asset.objects.get(id=object_id)
            current_assessment = AssetRiskAssessment.objects.filter(
                asset=obj
            ).first()
        else:  # organization
            obj = Organization.objects.get(id=object_id)
            current_assessment = OrganizationRiskAssessment.objects.filter(
                organization=obj
            ).first()
        
        if not current_assessment:
            raise Exception("No existing risk assessment found. Calculate initial risk first.")
        
        # Get all active contexts for this object
        existing_contexts = RiskContext.objects.filter(
            context_type=context_type,
            object_id=object_id,
            is_active=True
        ).order_by('added_at')
        
        # Combine all contexts
        all_contexts = [ctx.context_text for ctx in existing_contexts]
        all_contexts.append(context_text)
        combined_context = "\n\n".join(all_contexts)
        
        # Recalculate risk with context
        new_risk_data = self._recalculate_with_context(
            context_type, 
            obj, 
            current_assessment,
            combined_context
        )
        
        # Create context record
        context_record = RiskContext.objects.create(
            context_type=context_type,
            object_id=object_id,
            context_text=context_text,
            added_by=added_by,
            resulting_risk_score=new_risk_data['risk_score'],
            resulting_risk_level=new_risk_data['risk_level'],
            resulting_priority=new_risk_data['priority']
        )
        
        # Update assessment
        for key, value in new_risk_data.items():
            setattr(current_assessment, key, value)
        current_assessment.has_active_contexts = True
        current_assessment.active_context_count = existing_contexts.count() + 1
        current_assessment.save()
        
        return {
            'context_record': context_record,
            'updated_assessment': current_assessment,
            'risk_data': new_risk_data
        }
    
    def remove_context_and_recalculate(self, context_id):
        """
        Remove a context and recalculate risk without it
        
        Returns updated assessment
        """
        context = RiskContext.objects.get(id=context_id)
        context.is_active = False
        context.save()
        
        # Get object and current assessment
        context_type = context.context_type
        object_id = context.object_id
        
        if context_type == 'vulnerability':
            obj = Vulnerability.objects.get(id=object_id)
            current_assessment = VulnerabilityRiskAssessment.objects.get(
                vulnerability=obj
            )
        elif context_type == 'asset':
            obj = Asset.objects.get(id=object_id)
            current_assessment = AssetRiskAssessment.objects.get(asset=obj)
        else:
            obj = Organization.objects.get(id=object_id)
            current_assessment = OrganizationRiskAssessment.objects.get(
                organization=obj
            )
        
        # Get remaining active contexts
        remaining_contexts = RiskContext.objects.filter(
            context_type=context_type,
            object_id=object_id,
            is_active=True
        ).order_by('added_at')
        
        if remaining_contexts.exists():
            # Recalculate with remaining contexts
            combined_context = "\n\n".join([
                ctx.context_text for ctx in remaining_contexts
            ])
            new_risk_data = self._recalculate_with_context(
                context_type,
                obj,
                current_assessment,
                combined_context
            )
        else:
            # No contexts left, recalculate base risk
            if context_type == 'vulnerability':
                new_risk_data = self.risk_service.calculate_vulnerability_risk(obj)
            elif context_type == 'asset':
                new_risk_data = self.risk_service.calculate_asset_risk(obj)
            else:
                new_risk_data = self.risk_service.calculate_organization_risk(obj)
        
        # Update assessment
        for key, value in new_risk_data.items():
            setattr(current_assessment, key, value)
        
        current_assessment.active_context_count = remaining_contexts.count()
        current_assessment.has_active_contexts = remaining_contexts.exists()
        current_assessment.save()
        
        return current_assessment
    
    def _recalculate_with_context(self, context_type, obj, current_assessment, additional_context):
        """
        Recalculate risk with additional context
        
        Uses AI to understand the context and adjust risk calculation
        """
        if context_type == 'vulnerability':
            base_data = self._prepare_vulnerability_data_with_context(
                obj, 
                current_assessment, 
                additional_context
            )
            prompt = self._build_vulnerability_context_prompt(base_data)
        elif context_type == 'asset':
            base_data = self._prepare_asset_data_with_context(
                obj,
                current_assessment,
                additional_context
            )
            prompt = self._build_asset_context_prompt(base_data)
        else:
            base_data = self._prepare_organization_data_with_context(
                obj,
                current_assessment,
                additional_context
            )
            prompt = self._build_organization_context_prompt(base_data)
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity risk assessment expert.
                        You have been provided with additional context about a risk assessment.
                        Recalculate the risk score considering this new information.
                        The additional context may increase or decrease the risk.
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
            return self.risk_service._normalize_risk_response(result, context_type)
            
        except Exception as e:
            raise Exception(f"Failed to recalculate risk with context: {str(e)}")
    
    def find_similar_vulnerabilities(self, context_record):
        """
        Find similar vulnerabilities across the organization
        
        Args:
            context_record: RiskContext instance
            
        Returns:
            list of similar vulnerability IDs with similarity scores
        """
        if context_record.context_type != 'vulnerability':
            return []
        
        vulnerability = Vulnerability.objects.get(id=context_record.object_id)
        organization = vulnerability.asset.organization
        
        # Get all other vulnerabilities in the organization
        other_vulnerabilities = Vulnerability.objects.filter(
            asset__organization=organization
        ).exclude(id=vulnerability.id)
        
        if not other_vulnerabilities.exists():
            return []
        
        # Use AI to find similar vulnerabilities
        similar_vulns = self._find_similar_with_ai(
            vulnerability,
            context_record.context_text,
            other_vulnerabilities
        )
        
        return similar_vulns
    
    def start_context_application_chat(self, context_record, similar_vulnerabilities):
        """
        Start a chat session to ask user about applying context to similar vulnerabilities
        
        Returns chat session with initial message
        """
        chat_session = RiskContextChat.objects.create(
            source_context=context_record,
            similar_vulnerabilities=[str(v['id']) for v in similar_vulnerabilities],
            similar_vulnerabilities_metadata=similar_vulnerabilities  # Store full metadata
        )
        
        # Create initial system message
        system_msg = self._build_initial_chat_message(
            context_record,
            similar_vulnerabilities
        )
        
        RiskContextChatMessage.objects.create(
            chat_session=chat_session,
            role='assistant',
            content=system_msg
        )
        
        return chat_session
    
    def process_user_chat_response(self, chat_session, user_message):
        """
        Process user's chat response and determine intent
        
        Returns AI response with specific vulnerability IDs if user approves
        """
        # Get similar vulnerabilities metadata
        similar_vulns_metadata = getattr(
            chat_session, 
            'similar_vulnerabilities_metadata', 
            []
        )
        
        if not similar_vulns_metadata:
            # Fallback: reconstruct from IDs
            similar_vulns_metadata = self._reconstruct_vulnerability_metadata(
                chat_session.similar_vulnerabilities
            )
        
        # Use AI to understand user intent
        intent_response = self._analyze_user_intent(
            user_message,
            similar_vulns_metadata,
            chat_session.source_context.context_text
        )
        
        return intent_response
    
    def apply_context_to_similar_vulnerabilities(self, chat_session, user_approved, selected_vuln_ids=None):
        """
        Apply context to similar vulnerabilities based on user decision
        
        Args:
            chat_session: RiskContextChat instance
            user_approved: Boolean - whether user approved the application
            selected_vuln_ids: Optional list of specific vulnerability IDs to apply to
            
        Returns:
            dict with application results
        """
        if not user_approved:
            chat_session.user_approved = False
            chat_session.is_active = False
            chat_session.save()
            return {'applied': False, 'reason': 'User declined'}
        
        chat_session.user_approved = True
        
        # Get vulnerabilities to apply context to
        if selected_vuln_ids:
            vuln_ids = selected_vuln_ids
        else:
            vuln_ids = chat_session.similar_vulnerabilities
        
        source_context = chat_session.source_context
        applied_contexts = []
        results = []
        
        for vuln_id in vuln_ids:
            try:
                result = self.add_context_and_recalculate(
                    'vulnerability',
                    vuln_id,
                    f"Applied from similar vulnerability: {source_context.context_text}",
                    f"Auto-applied from {source_context.added_by}"
                )
                
                applied_contexts.append(str(result['context_record'].id))
                results.append({
                    'vulnerability_id': str(vuln_id),
                    'success': True,
                    'new_risk_score': result['risk_data']['risk_score']
                })
            except Exception as e:
                results.append({
                    'vulnerability_id': str(vuln_id),
                    'success': False,
                    'error': str(e)
                })
        
        chat_session.contexts_applied = applied_contexts
        chat_session.is_active = False
        chat_session.save()
        
        return {
            'applied': True,
            'total_attempted': len(vuln_ids),
            'successful': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'details': results
        }
    
    def _prepare_vulnerability_data_with_context(self, vulnerability, current_assessment, context):
        """Prepare vulnerability data with context for AI"""
        asset = vulnerability.asset
        
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
            },
            'asset': {
                'name': asset.name,
                'type': asset.asset_type,
                'technology_stack': asset.technology_stack,
            },
            'current_assessment': {
                'risk_score': current_assessment.risk_score,
                'risk_level': current_assessment.risk_level,
                'priority': current_assessment.priority,
                'reasoning': current_assessment.reasoning,
            },
            'additional_context': context
        }
    
    def _prepare_asset_data_with_context(self, asset, current_assessment, context):
        """Prepare asset data with context"""
        return {
            'asset': {
                'name': asset.name,
                'type': asset.asset_type,
                'description': asset.description,
                'technology_stack': asset.technology_stack,
            },
            'current_assessment': {
                'risk_score': current_assessment.risk_score,
                'risk_level': current_assessment.risk_level,
                'priority': current_assessment.priority,
                'reasoning': current_assessment.reasoning,
            },
            'additional_context': context
        }
    
    def _prepare_organization_data_with_context(self, organization, current_assessment, context):
        """Prepare organization data with context"""
        return {
            'organization': {
                'name': organization.name,
                'description': organization.description,
            },
            'current_assessment': {
                'risk_score': current_assessment.risk_score,
                'risk_level': current_assessment.risk_level,
                'reasoning': current_assessment.reasoning,
            },
            'additional_context': context
        }
    
    def _build_vulnerability_context_prompt(self, data):
        """Build prompt for vulnerability risk recalculation with context"""
        return f"""Recalculate the risk assessment for this vulnerability considering the additional context.

CURRENT ASSESSMENT:
Risk Score: {data['current_assessment']['risk_score']}
Risk Level: {data['current_assessment']['risk_level']}
Priority: {data['current_assessment']['priority']}
Current Reasoning: {data['current_assessment']['reasoning']}

VULNERABILITY DETAILS:
Title: {data['vulnerability']['title']}
Description: {data['vulnerability']['description']}
Impact: {data['vulnerability']['impact']}
Severity: {data['vulnerability']['severity']}
Category: {data['vulnerability']['category']}

ASSET CONTEXT:
Type: {data['asset']['type']}
Technology: {data['asset'].get('technology_stack', 'Not specified')}

ADDITIONAL CONTEXT PROVIDED:
{data['additional_context']}

Based on this additional context, recalculate the risk assessment. The context may provide:
- Information that increases risk (e.g., "this system handles PII data", "publicly exposed")
- Information that decreases risk (e.g., "behind firewall", "requires authentication", "not in production")
- Clarifications about business criticality, compensating controls, or threat landscape

Provide updated risk assessment with these exact keys:
- risk_score (0-100)
- risk_level (critical/high/medium/low/informational)
- priority (p1_immediate/p2_urgent/p3_high/p4_medium/p5_low)
- reasoning (explain how the additional context influenced the assessment)
- key_risk_factors (array of factors considering the new context)
- recommended_timeline (when to remediate)

Return as JSON."""
    
    def _build_asset_context_prompt(self, data):
        """Build prompt for asset risk recalculation with context"""
        return f"""Recalculate the risk assessment for this asset considering the additional context.

CURRENT ASSESSMENT:
Risk Score: {data['current_assessment']['risk_score']}
Risk Level: {data['current_assessment']['risk_level']}
Current Reasoning: {data['current_assessment']['reasoning']}

ASSET DETAILS:
Name: {data['asset']['name']}
Type: {data['asset']['type']}
Description: {data['asset'].get('description', 'N/A')}

ADDITIONAL CONTEXT:
{data['additional_context']}

Recalculate the risk considering this context. Return JSON with:
- risk_score, risk_level, priority, reasoning, key_risk_factors, remediation_priority, estimated_remediation_effort"""
    
    def _build_organization_context_prompt(self, data):
        """Build prompt for organization risk recalculation with context"""
        return f"""Recalculate the organization-wide risk considering the additional context.

CURRENT ASSESSMENT:
Risk Score: {data['current_assessment']['risk_score']}
Risk Level: {data['current_assessment']['risk_level']}

ORGANIZATION: {data['organization']['name']}

ADDITIONAL CONTEXT:
{data['additional_context']}

Recalculate the risk considering this context. Return JSON with:
- risk_score, risk_level, priority, reasoning, key_risk_factors, strategic_recommendations, focus_areas"""
    
    def _find_similar_with_ai(self, source_vulnerability, context_text, candidate_vulnerabilities):
        """Use AI to find similar vulnerabilities"""
        
        # Prepare candidate data
        candidates = []
        for vuln in candidate_vulnerabilities[:20]:  # Limit to 20 for token efficiency
            candidates.append({
                'id': str(vuln.id),
                'title': vuln.control_title,
                'description': vuln.control_description[:200],
                'category': vuln.category,
                'severity': vuln.severity,
                'asset_name': vuln.asset.name,
                'asset_type': vuln.asset.asset_type,
            })
        
        prompt = f"""Analyze these vulnerabilities to find ones similar to the source vulnerability where the given context would also apply.

SOURCE VULNERABILITY:
Title: {source_vulnerability.control_title}
Description: {source_vulnerability.control_description}
Category: {source_vulnerability.category}
Asset: {source_vulnerability.asset.name} ({source_vulnerability.asset.asset_type})

CONTEXT APPLIED TO SOURCE:
{context_text}

CANDIDATE VULNERABILITIES:
{json.dumps(candidates, indent=2)}

Identify vulnerabilities where this context would also be relevant and should be applied.
Consider:
- Similar vulnerability types
- Same category or related categories
- Similar asset types
- Whether the context reasoning applies

Return JSON with array of matching vulnerabilities:
{{
  "similar_vulnerabilities": [
    {{
      "id": "uuid",
      "similarity_reason": "why this context applies",
      "confidence": "high/medium/low"
    }}
  ]
}}"""
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing vulnerability similarities. Return only valid JSON."
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
            return result.get('similar_vulnerabilities', [])
            
        except Exception as e:
            print(f"Error finding similar vulnerabilities: {str(e)}")
            return []
    
    def _build_initial_chat_message(self, context_record, similar_vulnerabilities):
        """Build initial chat message suggesting context application"""
        
        vuln_count = len(similar_vulnerabilities)
        high_confidence = [v for v in similar_vulnerabilities if v.get('confidence') == 'high']
        medium_confidence = [v for v in similar_vulnerabilities if v.get('confidence') == 'medium']
        
        message = f"""I've analyzed the context you added and found **{vuln_count} similar vulnerabilities** in this organization where this context might also apply.

**Context you added:**
"{context_record.context_text}"

**Similar vulnerabilities found:**

"""
        
        # Group by confidence
        if high_confidence:
            message += f"\n### High Confidence Matches ({len(high_confidence)}):\n"
            for i, vuln in enumerate(high_confidence[:5], 1):
                vuln_obj = Vulnerability.objects.get(id=vuln['id'])
                message += f"{i}. **{vuln_obj.control_title}**\n"
                message += f"   - Asset: {vuln_obj.asset.name} ({vuln_obj.asset.asset_type})\n"
                message += f"   - Severity: {vuln_obj.severity}\n"
                message += f"   - Reason: {vuln['similarity_reason']}\n"
                message += f"   - ID: `{vuln['id']}`\n\n"
            
            if len(high_confidence) > 5:
                message += f"   ...and {len(high_confidence) - 5} more high-confidence matches\n\n"
        
        if medium_confidence:
            message += f"\n### Medium Confidence Matches ({len(medium_confidence)}):\n"
            for i, vuln in enumerate(medium_confidence[:3], 1):
                vuln_obj = Vulnerability.objects.get(id=vuln['id'])
                message += f"{i}. **{vuln_obj.control_title}**\n"
                message += f"   - Asset: {vuln_obj.asset.name}\n"
                message += f"   - Reason: {vuln['similarity_reason']}\n"
                message += f"   - ID: `{vuln['id']}`\n\n"
            
            if len(medium_confidence) > 3:
                message += f"   ...and {len(medium_confidence) - 3} more medium-confidence matches\n\n"
        
        message += f"""
---

**How would you like to proceed?**

You can respond with:
- "**Yes**" or "**Apply to all**" - Apply context to all {vuln_count} vulnerabilities
- "**High confidence only**" - Apply only to {len(high_confidence)} high-confidence matches
- "**Apply to specific IDs**" - I'll help you select specific vulnerabilities
- "**Show more details**" - Get more information about each vulnerability
- "**No**" or "**Skip**" - Keep context only on the original vulnerability

I recommend applying to at least the **{len(high_confidence)} high-confidence matches** to maintain consistent risk assessment across your organization."""
        
        return message
    
    def _analyze_user_intent(self, user_message, similar_vulns_metadata, context_text):
        """
        Use AI to analyze user's chat message and determine intent
        
        Returns structured response with action and vulnerability IDs
        """
        
        prompt = f"""Analyze this user's response to a vulnerability context application suggestion.

USER'S MESSAGE:
"{user_message}"

CONTEXT BEING APPLIED:
"{context_text}"

AVAILABLE SIMILAR VULNERABILITIES:
{json.dumps(similar_vulns_metadata, indent=2)}

Determine the user's intent and provide a structured response.

Possible intents:
1. "approve_all" - User wants to apply to all vulnerabilities
2. "approve_high_confidence" - User wants only high-confidence matches
3. "approve_specific" - User wants specific vulnerabilities (extract IDs if mentioned)
4. "need_more_info" - User wants more details
5. "decline" - User doesn't want to apply context

If the user says variations of:
- "yes", "apply", "apply to all", "do it", "proceed", "go ahead" → approve_all
- "high confidence", "high conf", "only high", "high priority" → approve_high_confidence
- Mentions specific IDs or numbers → approve_specific (extract the IDs)
- "more info", "details", "tell me more", "what about" → need_more_info
- "no", "skip", "not now", "cancel" → decline

Return JSON with:
{{
    "intent": "approve_all|approve_high_confidence|approve_specific|need_more_info|decline",
    "confidence": "high|medium|low",
    "vulnerability_ids": ["uuid1", "uuid2"],  // Empty if not approve_specific
    "reasoning": "Why you determined this intent",
    "user_friendly_message": "Confirmation message to show user with specific details"
}}

For the user_friendly_message, be specific about:
- How many vulnerabilities will be affected
- Which ones (list first 3-5 by name)
- What will happen next
- Include the actual vulnerability IDs in the message for transparency"""
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are an intelligent assistant helping with cybersecurity risk management.
                        Analyze user messages to understand their intent about applying security contexts.
                        Be accurate in intent detection and helpful in your responses.
                        Always include specific vulnerability IDs in your messages for transparency.
                        Return ONLY valid JSON, no markdown formatting."""
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
            
            # Enhance the response with actual vulnerability details
            result = self._enhance_intent_response(result, similar_vulns_metadata)
            
            return result
            
        except Exception as e:
            print(f"Error analyzing user intent: {str(e)}")
            # Fallback response
            return {
                "intent": "need_more_info",
                "confidence": "low",
                "vulnerability_ids": [],
                "reasoning": f"Error processing request: {str(e)}",
                "user_friendly_message": "I'm having trouble understanding your request. Could you please clarify? You can say 'yes' to apply to all, 'high confidence only', or 'no' to skip."
            }
    
    def _enhance_intent_response(self, intent_result, similar_vulns_metadata):
        """Enhance intent response with actual vulnerability details"""
        
        intent = intent_result['intent']
        
        # Get vulnerability IDs based on intent
        if intent == 'approve_all':
            vuln_ids = [v['id'] for v in similar_vulns_metadata]
        elif intent == 'approve_high_confidence':
            vuln_ids = [v['id'] for v in similar_vulns_metadata if v.get('confidence') == 'high']
        elif intent == 'approve_specific':
            vuln_ids = intent_result.get('vulnerability_ids', [])
        else:
            vuln_ids = []
        
        intent_result['vulnerability_ids'] = vuln_ids
        
        # Build detailed message with vulnerability information
        if vuln_ids:
            from .models import Vulnerability
            
            vulnerabilities = Vulnerability.objects.filter(
                id__in=vuln_ids
            ).select_related('asset')
            
            vuln_details = []
            for v in vulnerabilities[:5]:  # Show first 5
                vuln_details.append(f"- **{v.control_title}** on {v.asset.name} (ID: `{v.id}`)")
            
            if len(vulnerabilities) > 5:
                vuln_details.append(f"- ...and {len(vulnerabilities) - 5} more")
            
            details_text = "\n".join(vuln_details)
            
            # Update message with actual details
            intent_result['user_friendly_message'] = f"""Perfect! I'll apply the context to **{len(vuln_ids)} vulnerabilities**:

{details_text}

**Next Steps:**
To proceed, please call the apply endpoint:
```
POST /api/risk-context-chats/{{chat_session_id}}/apply_to_similar/
{{
    "approved": true,
    "selected_vulnerability_ids": {json.dumps(vuln_ids)}
}}
```

Or if you want to review these IDs first, let me know and I can provide more details about each vulnerability."""
        
        return intent_result
    
    def _reconstruct_vulnerability_metadata(self, vulnerability_ids):
        """Reconstruct vulnerability metadata from IDs"""
        
        vulnerabilities = Vulnerability.objects.filter(
            id__in=vulnerability_ids
        ).select_related('asset')
        
        metadata = []
        for vuln in vulnerabilities:
            metadata.append({
                'id': str(vuln.id),
                'title': vuln.control_title,
                'description': vuln.control_description[:200],
                'category': vuln.category,
                'severity': vuln.severity,
                'asset_name': vuln.asset.name,
                'asset_type': vuln.asset.asset_type,
                'confidence': 'medium'  # Default since we don't have original
            })
        
        return metadata