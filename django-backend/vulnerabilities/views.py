# views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.shortcuts import get_object_or_404

from .models import (
    Organization, Asset, Vulnerability, TesterArtifact,
    AIRemediation, RemediationFeedback
)
from .serializers import (
    OrganizationSerializer, AssetListSerializer, AssetDetailSerializer,
    VulnerabilityListSerializer, VulnerabilityDetailSerializer,
    TesterArtifactSerializer, AIRemediationSerializer,
    RemediationFeedbackSerializer, GenerateRemediationSerializer,
    SubmitFeedbackSerializer
)
from .ai_service import AIRemediationService
from .tasks import generate_remediation_task, process_feedback_task


class OrganizationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Organization
    List all organizations in the system
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class AssetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Assets (Applications and Servers)
    Filter by organization
    """
    queryset = Asset.objects.all()
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['organization', 'asset_type']
    search_fields = ['name', 'description', 'technology_stack']
    ordering_fields = ['name', 'created_at', 'asset_type']
    ordering = ['name']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return AssetDetailSerializer
        return AssetListSerializer

    @action(detail=False, methods=['get'])
    def by_organization(self, request):
        """Get all assets for a specific organization"""
        org_id = request.query_params.get('organization_id')
        if not org_id:
            return Response(
                {'error': 'organization_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        assets = self.queryset.filter(organization_id=org_id)
        serializer = self.get_serializer(assets, many=True)
        return Response(serializer.data)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Vulnerabilities
    Filter by asset, severity, category
    """
    queryset = Vulnerability.objects.all()
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['asset', 'severity', 'category', 'owasp']
    search_fields = ['control_title', 'control_description', 'cve_id', 'cwe_id']
    ordering_fields = ['severity', 'created_at', 'control_title']
    ordering = ['-severity', '-created_at']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return VulnerabilityDetailSerializer
        return VulnerabilityListSerializer

    @action(detail=False, methods=['get'])
    def by_asset(self, request):
        """Get all vulnerabilities for a specific asset"""
        asset_id = request.query_params.get('asset_id')
        if not asset_id:
            return Response(
                {'error': 'asset_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        vulnerabilities = self.queryset.filter(asset_id=asset_id)
        serializer = self.get_serializer(vulnerabilities, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def remediations(self, request, pk=None):
        """Get all AI remediations for a vulnerability"""
        vulnerability = self.get_object()
        remediations = AIRemediation.objects.filter(vulnerability=vulnerability)
        serializer = AIRemediationSerializer(remediations, many=True)
        return Response(serializer.data)


class TesterArtifactViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Tester Artifacts (Screenshots, files)
    """
    queryset = TesterArtifact.objects.all()
    serializer_class = TesterArtifactSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['vulnerability']

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context


class AIRemediationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for AI-powered vulnerability remediation
    """
    queryset = AIRemediation.objects.all()
    serializer_class = AIRemediationSerializer

    @action(detail=False, methods=['post'])
    def generate(self, request):
        """
        Generate AI remediation for a vulnerability
        POST /api/remediations/generate/
        {
            "vulnerability_id": "uuid",
            "regenerate": false
        }
        """
        serializer = GenerateRemediationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        vulnerability_id = serializer.validated_data['vulnerability_id']
        regenerate = serializer.validated_data.get('regenerate', False)
        
        vulnerability = get_object_or_404(Vulnerability, id=vulnerability_id)
        
        # Check if using async task queue or synchronous
        use_async = getattr(request, 'use_async', False)
        
        if use_async:
            # Queue the task with RabbitMQ/Celery
            task = generate_remediation_task.delay(str(vulnerability_id), regenerate)
            return Response({
                'message': 'Remediation generation started',
                'task_id': task.id,
                'vulnerability_id': str(vulnerability_id)
            }, status=status.HTTP_202_ACCEPTED)
        else:
            # Synchronous generation
            try:
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
                
                serializer = AIRemediationSerializer(remediation)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

    @action(detail=True, methods=['post'])
    def regenerate(self, request, pk=None):
        """
        Regenerate remediation with different approach
        POST /api/remediations/{id}/regenerate/
        """
        original_remediation = self.get_object()
        vulnerability = original_remediation.vulnerability
        
        try:
            ai_service = AIRemediationService()
            remediation_steps, prompt_used = ai_service.generate_remediation(
                vulnerability, regenerate=True
            )
            
            # Create new remediation record
            new_remediation = AIRemediation.objects.create(
                vulnerability=vulnerability,
                prompt_used=prompt_used,
                remediation_steps=remediation_steps,
                model_used='gpt-4o-mini',
                regeneration_count=original_remediation.regeneration_count + 1
            )
            
            serializer = AIRemediationSerializer(new_remediation)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RemediationFeedbackViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling feedback on AI remediations
    """
    queryset = RemediationFeedback.objects.all()
    serializer_class = RemediationFeedbackSerializer

    @action(detail=False, methods=['post'])
    def submit(self, request):
        """
        Submit feedback for a remediation
        POST /api/feedback/submit/
        {
            "remediation_id": "uuid",
            "was_helpful": true/false,
            "comments": "optional comments",
            "user_steps": "optional user-provided correct steps"
        }
        """
        serializer = SubmitFeedbackSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        remediation_id = serializer.validated_data['remediation_id']
        was_helpful = serializer.validated_data['was_helpful']
        comments = serializer.validated_data.get('comments', '')
        user_steps = serializer.validated_data.get('user_steps', '')
        
        remediation = get_object_or_404(AIRemediation, id=remediation_id)
        
        # Update remediation
        remediation.is_helpful = was_helpful
        remediation.user_feedback = comments
        if user_steps:
            remediation.user_provided_steps = user_steps
        remediation.save()
        
        # Check if using async task queue or synchronous
        use_async = getattr(request, 'use_async', False)
        
        if use_async:
            # Queue the feedback processing
            task = process_feedback_task.delay(
                str(remediation_id),
                was_helpful,
                comments,
                user_steps
            )
            
            feedback = RemediationFeedback.objects.create(
                remediation=remediation,
                was_helpful=was_helpful,
                comments=comments,
                user_steps=user_steps
            )
            
            return Response({
                'message': 'Feedback received and queued for processing',
                'task_id': task.id,
                'feedback_id': str(feedback.id)
            }, status=status.HTTP_202_ACCEPTED)
        else:
            # Synchronous processing
            try:
                ai_service = AIRemediationService()
                vector_id = ai_service.process_feedback(
                    remediation,
                    was_helpful,
                    comments,
                    user_steps
                )
                
                feedback = RemediationFeedback.objects.create(
                    remediation=remediation,
                    was_helpful=was_helpful,
                    comments=comments,
                    user_steps=user_steps,
                    stored_in_vector_db=bool(vector_id),
                    vector_db_id=vector_id or ''
                )
                
                response_serializer = RemediationFeedbackSerializer(feedback)
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )