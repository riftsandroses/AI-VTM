# tasks.py
from celery import shared_task
from django.shortcuts import get_object_or_404
from .models import Vulnerability, AIRemediation, RemediationFeedback
from .ai_service import AIRemediationService
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def generate_remediation_task(self, vulnerability_id, regenerate=False):
    """
    Asynchronous task to generate AI remediation
    Uses RabbitMQ as message broker
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        
        ai_service = AIRemediationService()
        remediation_steps, prompt_used = ai_service.generate_remediation(
            vulnerability, regenerate
        )
        
        # Create remediation record
        remediation = AIRemediation.objects.create(
            vulnerability=vulnerability,
            prompt_used=prompt_used,
            remediation_steps=remediation_steps,
            model_used='gpt-4o-mini',
            regeneration_count=1 if regenerate else 0
        )
        
        logger.info(f"Successfully generated remediation {remediation.id} for vulnerability {vulnerability_id}")
        
        return {
            'status': 'success',
            'remediation_id': str(remediation.id),
            'vulnerability_id': str(vulnerability_id)
        }
        
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found")
        return {
            'status': 'error',
            'message': f'Vulnerability {vulnerability_id} not found'
        }
    except Exception as e:
        logger.error(f"Error generating remediation: {str(e)}")
        # Retry the task
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def process_feedback_task(self, remediation_id, was_helpful, comments='', user_steps=''):
    """
    Asynchronous task to process feedback and update vector DB
    Uses RabbitMQ as message broker
    """
    try:
        remediation = AIRemediation.objects.get(id=remediation_id)
        
        ai_service = AIRemediationService()
        vector_id = ai_service.process_feedback(
            remediation,
            was_helpful,
            comments,
            user_steps
        )
        
        # Update or create feedback record
        feedback, created = RemediationFeedback.objects.get_or_create(
            remediation=remediation,
            defaults={
                'was_helpful': was_helpful,
                'comments': comments,
                'user_steps': user_steps,
                'stored_in_vector_db': bool(vector_id),
                'vector_db_id': vector_id or ''
            }
        )
        
        if not created:
            feedback.was_helpful = was_helpful
            feedback.comments = comments
            feedback.user_steps = user_steps
            feedback.stored_in_vector_db = bool(vector_id)
            feedback.vector_db_id = vector_id or ''
            feedback.save()
        
        logger.info(f"Successfully processed feedback for remediation {remediation_id}")
        
        return {
            'status': 'success',
            'feedback_id': str(feedback.id),
            'stored_in_vector_db': bool(vector_id)
        }
        
    except AIRemediation.DoesNotExist:
        logger.error(f"Remediation {remediation_id} not found")
        return {
            'status': 'error',
            'message': f'Remediation {remediation_id} not found'
        }
    except Exception as e:
        logger.error(f"Error processing feedback: {str(e)}")
        # Retry the task
        raise self.retry(exc=e, countdown=60)


@shared_task
def cleanup_old_remediations():
    """
    Periodic task to clean up old, unhelpful remediations
    Can be scheduled with Celery Beat
    """
    from django.utils import timezone
    from datetime import timedelta
    
    # Delete remediations older than 90 days that were marked as not helpful
    cutoff_date = timezone.now() - timedelta(days=90)
    
    deleted_count = AIRemediation.objects.filter(
        is_helpful=False,
        created_at__lt=cutoff_date
    ).delete()[0]
    
    logger.info(f"Cleaned up {deleted_count} old unhelpful remediations")
    
    return {
        'status': 'success',
        'deleted_count': deleted_count
    }


@shared_task
def update_vector_db_from_helpful_remediations():
    """
    Periodic task to ensure all helpful remediations are in vector DB
    Can be scheduled with Celery Beat
    """
    ai_service = AIRemediationService()
    
    # Find helpful remediations without feedback entries
    helpful_remediations = AIRemediation.objects.filter(
        is_helpful=True
    ).exclude(
        feedback_entries__stored_in_vector_db=True
    )
    
    updated_count = 0
    for remediation in helpful_remediations:
        try:
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
            
            vector_id = ai_service.vector_db.add_successful_remediation(
                vuln_data,
                asset_data,
                remediation.remediation_steps,
                remediation.user_provided_steps if remediation.user_provided_steps else None
            )
            
            # Create feedback entry
            RemediationFeedback.objects.create(
                remediation=remediation,
                was_helpful=True,
                stored_in_vector_db=True,
                vector_db_id=vector_id
            )
            
            updated_count += 1
            
        except Exception as e:
            logger.error(f"Error updating vector DB for remediation {remediation.id}: {str(e)}")
            continue
    
    logger.info(f"Updated vector DB with {updated_count} helpful remediations")
    
    return {
        'status': 'success',
        'updated_count': updated_count
    }