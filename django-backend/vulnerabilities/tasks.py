# tasks.py
from celery import shared_task
from django.shortcuts import get_object_or_404
from django.utils import timezone
from datetime import timedelta
from .ai_service import AIRemediationService
from .models import (
    Vulnerability, AIRemediation, RemediationFeedback,
    Asset, Organization, VulnerabilityRiskAssessment, 
    AssetRiskAssessment, OrganizationRiskAssessment, RiskAssessmentHistory
)
from .risk_scoring_service import RiskScoringService
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


@shared_task(bind=True, max_retries=3)
def calculate_vulnerability_risk_task(self, vulnerability_id, recalculate=False):
    """
    Asynchronous task to calculate vulnerability risk assessment
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        
        # Check if assessment already exists
        existing_assessment = VulnerabilityRiskAssessment.objects.filter(
            vulnerability=vulnerability
        ).first()
        
        if existing_assessment and not recalculate:
            logger.info(f"Risk assessment already exists for vulnerability {vulnerability_id}")
            return {
                'status': 'exists',
                'assessment_id': str(existing_assessment.id),
                'vulnerability_id': str(vulnerability_id)
            }
        
        risk_service = RiskScoringService()
        risk_data = risk_service.calculate_vulnerability_risk(vulnerability)
        
        # Store previous values for history
        previous_score = None
        previous_level = None
        
        if existing_assessment:
            previous_score = existing_assessment.risk_score
            previous_level = existing_assessment.risk_level
            
            # Update existing
            for key, value in risk_data.items():
                setattr(existing_assessment, key, value)
            existing_assessment.save()
            
            assessment = existing_assessment
        else:
            # Create new
            assessment = VulnerabilityRiskAssessment.objects.create(
                vulnerability=vulnerability,
                **risk_data
            )
        
        # Create history record
        RiskAssessmentHistory.objects.create(
            assessment_type='vulnerability',
            object_id=vulnerability.id,
            object_name=vulnerability.control_title,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason='Automated AI risk calculation'
        )
        
        logger.info(f"Successfully calculated risk for vulnerability {vulnerability_id}")
        
        return {
            'status': 'success',
            'assessment_id': str(assessment.id),
            'vulnerability_id': str(vulnerability_id),
            'risk_score': assessment.risk_score,
            'risk_level': assessment.risk_level
        }
        
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found")
        return {
            'status': 'error',
            'message': f'Vulnerability {vulnerability_id} not found'
        }
    except Exception as e:
        logger.error(f"Error calculating vulnerability risk: {str(e)}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def calculate_asset_risk_task(self, asset_id, recalculate=False):
    """
    Asynchronous task to calculate asset risk assessment
    """
    try:
        asset = Asset.objects.get(id=asset_id)
        
        existing_assessment = AssetRiskAssessment.objects.filter(
            asset=asset
        ).first()
        
        if existing_assessment and not recalculate:
            logger.info(f"Risk assessment already exists for asset {asset_id}")
            return {
                'status': 'exists',
                'assessment_id': str(existing_assessment.id),
                'asset_id': str(asset_id)
            }
        
        risk_service = RiskScoringService()
        risk_data = risk_service.calculate_asset_risk(asset)
        
        previous_score = None
        previous_level = None
        
        if existing_assessment:
            previous_score = existing_assessment.risk_score
            previous_level = existing_assessment.risk_level
            
            for key, value in risk_data.items():
                setattr(existing_assessment, key, value)
            existing_assessment.save()
            
            assessment = existing_assessment
        else:
            assessment = AssetRiskAssessment.objects.create(
                asset=asset,
                **risk_data
            )
        
        # Create history
        RiskAssessmentHistory.objects.create(
            assessment_type='asset',
            object_id=asset.id,
            object_name=asset.name,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason='Automated AI risk calculation'
        )
        
        logger.info(f"Successfully calculated risk for asset {asset_id}")
        
        return {
            'status': 'success',
            'assessment_id': str(assessment.id),
            'asset_id': str(asset_id),
            'risk_score': assessment.risk_score,
            'risk_level': assessment.risk_level
        }
        
    except Asset.DoesNotExist:
        logger.error(f"Asset {asset_id} not found")
        return {
            'status': 'error',
            'message': f'Asset {asset_id} not found'
        }
    except Exception as e:
        logger.error(f"Error calculating asset risk: {str(e)}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def calculate_organization_risk_task(self, organization_id, recalculate=False):
    """
    Asynchronous task to calculate organization risk assessment
    """
    try:
        organization = Organization.objects.get(id=organization_id)
        
        existing_assessment = OrganizationRiskAssessment.objects.filter(
            organization=organization
        ).first()
        
        if existing_assessment and not recalculate:
            logger.info(f"Risk assessment already exists for organization {organization_id}")
            return {
                'status': 'exists',
                'assessment_id': str(existing_assessment.id),
                'organization_id': str(organization_id)
            }
        
        risk_service = RiskScoringService()
        risk_data = risk_service.calculate_organization_risk(organization)
        
        previous_score = None
        previous_level = None
        
        if existing_assessment:
            previous_score = existing_assessment.risk_score
            previous_level = existing_assessment.risk_level
            
            for key, value in risk_data.items():
                setattr(existing_assessment, key, value)
            existing_assessment.save()
            
            assessment = existing_assessment
        else:
            assessment = OrganizationRiskAssessment.objects.create(
                organization=organization,
                **risk_data
            )
        
        # Create history
        RiskAssessmentHistory.objects.create(
            assessment_type='organization',
            object_id=organization.id,
            object_name=organization.name,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason='Automated AI risk calculation'
        )
        
        logger.info(f"Successfully calculated risk for organization {organization_id}")
        
        return {
            'status': 'success',
            'assessment_id': str(assessment.id),
            'organization_id': str(organization_id),
            'risk_score': assessment.risk_score,
            'risk_level': assessment.risk_level
        }
        
    except Organization.DoesNotExist:
        logger.error(f"Organization {organization_id} not found")
        return {
            'status': 'error',
            'message': f'Organization {organization_id} not found'
        }
    except Exception as e:
        logger.error(f"Error calculating organization risk: {str(e)}")
        raise self.retry(exc=e, countdown=60)


@shared_task
def bulk_calculate_vulnerability_risks(recalculate=False):
    """
    Bulk calculate risk assessments for all vulnerabilities
    Useful for periodic recalculation
    """
    vulnerabilities = Vulnerability.objects.all()
    
    if not recalculate:
        vulnerabilities = vulnerabilities.filter(risk_assessment__isnull=True)
    
    total = vulnerabilities.count()
    processed = 0
    errors = 0
    
    for vulnerability in vulnerabilities:
        try:
            calculate_vulnerability_risk_task.delay(
                str(vulnerability.id), 
                recalculate
            )
            processed += 1
        except Exception as e:
            logger.error(f"Error queuing vulnerability {vulnerability.id}: {str(e)}")
            errors += 1
    
    logger.info(f"Queued {processed} vulnerability risk calculations, {errors} errors")
    
    return {
        'status': 'success',
        'total': total,
        'processed': processed,
        'errors': errors
    }


@shared_task
def bulk_calculate_asset_risks(recalculate=False):
    """
    Bulk calculate risk assessments for all assets
    """
    assets = Asset.objects.all()
    
    if not recalculate:
        assets = assets.filter(risk_assessment__isnull=True)
    
    total = assets.count()
    processed = 0
    errors = 0
    
    for asset in assets:
        try:
            calculate_asset_risk_task.delay(str(asset.id), recalculate)
            processed += 1
        except Exception as e:
            logger.error(f"Error queuing asset {asset.id}: {str(e)}")
            errors += 1
    
    logger.info(f"Queued {processed} asset risk calculations, {errors} errors")
    
    return {
        'status': 'success',
        'total': total,
        'processed': processed,
        'errors': errors
    }


@shared_task
def bulk_calculate_organization_risks(recalculate=False):
    """
    Bulk calculate risk assessments for all organizations
    """
    organizations = Organization.objects.all()
    
    if not recalculate:
        organizations = organizations.filter(risk_assessment__isnull=True)
    
    total = organizations.count()
    processed = 0
    errors = 0
    
    for organization in organizations:
        try:
            calculate_organization_risk_task.delay(
                str(organization.id), 
                recalculate
            )
            processed += 1
        except Exception as e:
            logger.error(f"Error queuing organization {organization.id}: {str(e)}")
            errors += 1
    
    logger.info(f"Queued {processed} organization risk calculations, {errors} errors")
    
    return {
        'status': 'success',
        'total': total,
        'processed': processed,
        'errors': errors
    }


@shared_task
def periodic_risk_recalculation():
    """
    Periodic task to recalculate all risk assessments
    Can be scheduled with Celery Beat to run weekly or monthly
    """
    
    # Recalculate assessments older than 7 days
    cutoff_date = timezone.now() - timedelta(days=7)
    
    # Vulnerability risks
    old_vuln_assessments = VulnerabilityRiskAssessment.objects.filter(
        last_updated__lt=cutoff_date
    )
    
    for assessment in old_vuln_assessments:
        try:
            calculate_vulnerability_risk_task.delay(
                str(assessment.vulnerability.id), 
                recalculate=True
            )
        except Exception as e:
            logger.error(f"Error queuing vulnerability risk recalculation: {str(e)}")
    
    # Asset risks
    old_asset_assessments = AssetRiskAssessment.objects.filter(
        last_updated__lt=cutoff_date
    )
    
    for assessment in old_asset_assessments:
        try:
            calculate_asset_risk_task.delay(
                str(assessment.asset.id), 
                recalculate=True
            )
        except Exception as e:
            logger.error(f"Error queuing asset risk recalculation: {str(e)}")
    
    # Organization risks
    old_org_assessments = OrganizationRiskAssessment.objects.filter(
        last_updated__lt=cutoff_date
    )
    
    for assessment in old_org_assessments:
        try:
            calculate_organization_risk_task.delay(
                str(assessment.organization.id), 
                recalculate=True
            )
        except Exception as e:
            logger.error(f"Error queuing organization risk recalculation: {str(e)}")
    
    logger.info("Periodic risk recalculation completed")
    
    return {
        'status': 'success',
        'vulnerabilities': old_vuln_assessments.count(),
        'assets': old_asset_assessments.count(),
        'organizations': old_org_assessments.count()
    }


@shared_task
def cascade_risk_calculation(vulnerability_id):
    """
    When a vulnerability is added/updated, cascade risk calculations
    1. Calculate vulnerability risk
    2. Recalculate parent asset risk
    3. Recalculate parent organization risk
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        asset = vulnerability.asset
        organization = asset.organization
        
        # Calculate vulnerability risk
        vuln_result = calculate_vulnerability_risk_task.delay(
            str(vulnerability_id), 
            recalculate=True
        )
        
        # Calculate asset risk
        asset_result = calculate_asset_risk_task.delay(
            str(asset.id), 
            recalculate=True
        )
        
        # Calculate organization risk
        org_result = calculate_organization_risk_task.delay(
            str(organization.id), 
            recalculate=True
        )
        
        logger.info(f"Cascade risk calculation triggered for vulnerability {vulnerability_id}")
        
        return {
            'status': 'success',
            'vulnerability_id': str(vulnerability_id),
            'asset_id': str(asset.id),
            'organization_id': str(organization.id)
        }
        
    except Exception as e:
        logger.error(f"Error in cascade risk calculation: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }