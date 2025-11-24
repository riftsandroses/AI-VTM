# chat_service.py
from django.conf import settings
from openai import OpenAI
from .models import RemediationChat, ChatMessage, RemediationUpdate, AIRemediation
import json

client = OpenAI(api_key=settings.OPENAI_API_KEY)


class RemediationChatService:
    """Service for handling chat conversations about vulnerability remediations"""
    
    def __init__(self):
        self.model = "gpt-4o-mini"
        self.max_context_messages = 20  # Limit context window
    
    def start_chat_session(self, remediation):
        """Start a new chat session for a remediation"""
        chat_session = RemediationChat.objects.create(
            remediation=remediation
        )
        
        # Create initial system message with context
        system_message = self._build_system_context(remediation)
        ChatMessage.objects.create(
            chat_session=chat_session,
            role='system',
            content=system_message
        )
        
        return chat_session
    
    def get_or_create_active_session(self, remediation):
        """Get active chat session or create new one"""
        active_session = RemediationChat.objects.filter(
            remediation=remediation,
            is_active=True
        ).first()
        
        if not active_session:
            active_session = self.start_chat_session(remediation)
        
        return active_session
    
    def send_message(self, chat_session, user_message):
        """Send a message and get AI response"""
        # Save user message
        ChatMessage.objects.create(
            chat_session=chat_session,
            role='user',
            content=user_message
        )
        
        # Get conversation history
        conversation_history = self._get_conversation_history(chat_session)
        
        # Call OpenAI API
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=conversation_history,
                temperature=0.7,
                max_tokens=2000
            )
            
            assistant_message = response.choices[0].message.content.strip()
            
            # Save assistant response
            ChatMessage.objects.create(
                chat_session=chat_session,
                role='assistant',
                content=assistant_message
            )
            
            # Update chat session timestamp
            chat_session.save()
            
            return assistant_message
            
        except Exception as e:
            raise Exception(f"Failed to get chat response: {str(e)}")
    
    def update_remediation_from_chat(self, chat_session, update_reason="Based on chat clarifications"):
        """Generate updated remediation based on chat conversation"""
        remediation = chat_session.remediation
        
        # Get conversation history
        messages = ChatMessage.objects.filter(
            chat_session=chat_session,
            role__in=['user', 'assistant']
        ).order_by('created_at')
        
        # Build conversation summary
        conversation_summary = "\n".join([
            f"{msg.role.upper()}: {msg.content}"
            for msg in messages
        ])
        
        # Create prompt for updated remediation
        update_prompt = self._build_update_prompt(remediation, conversation_summary)
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert. Based on the conversation history, "
                            "generate an improved and more detailed remediation plan. "
                            "Incorporate all clarifications and additional context from the conversation."
                        )
                    },
                    {
                        "role": "user",
                        "content": update_prompt
                    }
                ],
                temperature=0.5,
                max_tokens=2500
            )
            
            updated_steps = response.choices[0].message.content.strip()
            
            # Create update record
            RemediationUpdate.objects.create(
                remediation=remediation,
                chat_session=chat_session,
                previous_steps=remediation.remediation_steps,
                updated_steps=updated_steps,
                update_reason=update_reason
            )
            
            # Update the remediation
            remediation.remediation_steps = updated_steps
            remediation.regeneration_count += 1
            remediation.save()
            
            return updated_steps
            
        except Exception as e:
            raise Exception(f"Failed to update remediation: {str(e)}")
    
    def end_chat_session(self, chat_session):
        """Mark chat session as inactive"""
        chat_session.is_active = False
        chat_session.save()
    
    def _build_system_context(self, remediation):
        """Build initial system message with full context"""
        vulnerability = remediation.vulnerability
        asset = vulnerability.asset
        
        context = f"""You are a cybersecurity expert assistant helping with vulnerability remediation.

VULNERABILITY DETAILS:
Title: {vulnerability.control_title}
Description: {vulnerability.control_description}
Impact: {vulnerability.control_impact}
Severity: {vulnerability.severity}
Category: {vulnerability.category}
OWASP: {vulnerability.owasp or 'N/A'}
CVE: {vulnerability.cve_id or 'N/A'}
CWE: {vulnerability.cwe_id or 'N/A'}

ASSET CONTEXT:
Name: {asset.name}
Type: {asset.asset_type}
Technology Stack: {asset.technology_stack or 'Not specified'}
OS: {asset.os_version or 'Not specified'}
Framework: {asset.framework_version or 'Not specified'}

CURRENT REMEDIATION STEPS:
{remediation.remediation_steps}

Your role is to:
1. Answer questions about the vulnerability and remediation
2. Provide clarifications on any steps
3. Suggest improvements or alternatives
4. Address specific concerns about implementation
5. Help adapt the remediation to specific environments

Be concise, practical, and security-focused. Provide code examples or commands when helpful."""
        
        return context
    
    def _get_conversation_history(self, chat_session):
        """Get formatted conversation history for API"""
        messages = ChatMessage.objects.filter(
            chat_session=chat_session
        ).order_by('created_at')
        
        # Limit to recent messages to avoid token limits
        messages = messages[:self.max_context_messages]
        
        return [
            {
                "role": msg.role,
                "content": msg.content
            }
            for msg in messages
        ]
    
    def _build_update_prompt(self, remediation, conversation_summary):
        """Build prompt for generating updated remediation"""
        vulnerability = remediation.vulnerability
        
        prompt = f"""Based on the following conversation about a vulnerability remediation, 
generate an improved and more comprehensive remediation plan.

ORIGINAL REMEDIATION:
{remediation.remediation_steps}

CONVERSATION HISTORY:
{conversation_summary}

REQUIREMENTS:
1. Incorporate all clarifications and improvements discussed in the conversation
2. Maintain the structure and clarity of the original remediation
3. Add any missing details that were clarified
4. Address any concerns or edge cases mentioned
5. Keep the same level of technical detail
6. Ensure all steps are actionable and specific

Generate the updated remediation steps now:"""
        
        return prompt
    
    def get_chat_summary(self, chat_session):
        """Generate a summary of the chat conversation"""
        messages = ChatMessage.objects.filter(
            chat_session=chat_session,
            role__in=['user', 'assistant']
        ).order_by('created_at')
        
        if messages.count() == 0:
            return "No messages in this chat session."
        
        conversation_text = "\n".join([
            f"{msg.role.upper()}: {msg.content}"
            for msg in messages
        ])
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "Summarize this conversation about vulnerability remediation in 2-3 paragraphs."
                    },
                    {
                        "role": "user",
                        "content": conversation_text
                    }
                ],
                temperature=0.5,
                max_tokens=500
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            return f"Failed to generate summary: {str(e)}"