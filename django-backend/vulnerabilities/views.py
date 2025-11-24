# ---------------------------------
# Standard Library
# ---------------------------------
from datetime import timedelta

# ---------------------------------
# Django
# ---------------------------------
from django.db.models import Q, Count, Avg, Max, Min
from django.shortcuts import get_object_or_404
from django.utils import timezone

# ---------------------------------
# Third-Party
# ---------------------------------
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

# ---------------------------------
# Local App - Models
# ---------------------------------
from .models import (
    AIRemediation,
    Asset,
    AssetRiskAssessment,
    ChatMessage,
    Organization,
    OrganizationRiskAssessment,
    RemediationChat,
    RemediationFeedback,
    RemediationUpdate,
    RiskAssessmentHistory,
    TesterArtifact,
    Vulnerability,
    VulnerabilityRiskAssessment,
)

# ---------------------------------
# Local App - Serializers
# ---------------------------------
from .serializers import (
    AIRemediationSerializer,
    AssetDetailSerializer,
    AssetListSerializer,
    AssetRiskAssessmentSerializer,
    AssetWithRiskSerializer,
    BulkRiskCalculationSerializer,
    CalculateAssetRiskSerializer,
    CalculateOrganizationRiskSerializer,
    CalculateVulnerabilityRiskSerializer,
    ChatMessageSerializer,
    GenerateRemediationSerializer,
    OrganizationRiskAssessmentSerializer,
    OrganizationSerializer,
    OrganizationWithRiskSerializer,
    OverrideRiskAssessmentSerializer,
    RemediationChatDetailSerializer,
    RemediationChatSerializer,
    RemediationFeedbackSerializer,
    RemediationUpdateSerializer,
    RiskAssessmentHistorySerializer,
    SendChatMessageSerializer,
    SubmitFeedbackSerializer,
    TesterArtifactSerializer,
    VulnerabilityDetailSerializer,
    VulnerabilityListSerializer,
    VulnerabilityRiskAssessmentSerializer,
    VulnerabilityWithRiskSerializer,
)

# ---------------------------------
# Local App - Services & Tasks
# ---------------------------------
from .ai_service import AIRemediationService
from .chat_service import RemediationChatService
from .risk_scoring_service import RiskScoringService
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

    @action(detail=True, methods=['get'])
    def with_risk(self, request, pk=None):
        """
        Get organization with risk assessment
        GET /api/organizations/{id}/with_risk/
        """
        organization = self.get_object()
        
        # Import the serializer at the top of your file if not already imported
        from .serializers import OrganizationWithRiskSerializer
        
        serializer = OrganizationWithRiskSerializer(organization)
        return Response(serializer.data)


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
    
    @action(detail=True, methods=['get'])
    def with_risk(self, request, pk=None):
        """
        Get asset with risk assessment
        GET /api/assets/{id}/with_risk/
        """
        asset = self.get_object()
        
        # Import the serializer at the top of your file if not already imported
        from .serializers import AssetWithRiskSerializer
        
        serializer = AssetWithRiskSerializer(asset)
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
    
    @action(detail=True, methods=['get'])
    def with_risk(self, request, pk=None):
        """
        Get vulnerability with risk assessment
        GET /api/vulnerabilities/{id}/with_risk/
        """
        vulnerability = self.get_object()
        
        # Import the serializer at the top of your file if not already imported
        from .serializers import VulnerabilityWithRiskSerializer
        
        serializer = VulnerabilityWithRiskSerializer(vulnerability)
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


class RemediationChatViewSet(viewsets.ModelViewSet):
    """
    ViewSet for chat conversations about remediations
    """
    queryset = RemediationChat.objects.all()
    serializer_class = RemediationChatSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['remediation', 'is_active']
    search_fields = ['remediation__vulnerability__control_title', 'messages__content']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']

    @action(detail=False, methods=['post'])
    def send_message(self, request):
        """
        Send a message in a chat session
        POST /api/chat/send_message/
        {
            "remediation_id": "uuid",
            "message": "Can you explain step 3 in more detail?",
            "chat_session_id": "uuid"  // optional, will create new if not provided
        }
        """
        serializer = SendChatMessageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        remediation_id = serializer.validated_data['remediation_id']
        message = serializer.validated_data['message']
        chat_session_id = serializer.validated_data.get('chat_session_id')
        
        remediation = get_object_or_404(AIRemediation, id=remediation_id)
        
        try:
            chat_service = RemediationChatService()
            
            # Get or create chat session
            if chat_session_id:
                chat_session = get_object_or_404(RemediationChat, id=chat_session_id)
            else:
                chat_session = chat_service.get_or_create_active_session(remediation)
            
            # Send message and get response
            assistant_response = chat_service.send_message(chat_session, message)
            
            # Get updated conversation
            messages = ChatMessage.objects.filter(
                chat_session=chat_session
            ).order_by('created_at')
            
            return Response({
                'chat_session_id': str(chat_session.id),
                'user_message': message,
                'assistant_response': assistant_response,
                'messages': ChatMessageSerializer(messages, many=True).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """
        Get all messages in a chat session
        GET /api/chat/{id}/messages/
        """
        chat_session = self.get_object()
        messages = ChatMessage.objects.filter(chat_session=chat_session)
        serializer = ChatMessageSerializer(messages, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def update_remediation(self, request, pk=None):
        """
        Generate updated remediation based on chat conversation
        POST /api/chat/{id}/update_remediation/
        {
            "update_reason": "Optional reason for update"
        }
        """
        chat_session = self.get_object()
        update_reason = request.data.get('update_reason', 'Based on chat clarifications')
        
        try:
            chat_service = RemediationChatService()
            updated_steps = chat_service.update_remediation_from_chat(
                chat_session,
                update_reason
            )
            
            return Response({
                'message': 'Remediation updated successfully',
                'updated_steps': updated_steps,
                'remediation_id': str(chat_session.remediation.id)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def end_session(self, request, pk=None):
        """
        End an active chat session
        POST /api/chat/{id}/end_session/
        """
        chat_session = self.get_object()
        chat_service = RemediationChatService()
        chat_service.end_chat_session(chat_session)
        
        return Response({
            'message': 'Chat session ended',
            'session_id': str(chat_session.id)
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """
        Get a summary of the chat conversation
        GET /api/chat/{id}/summary/
        """
        chat_session = self.get_object()
        
        try:
            chat_service = RemediationChatService()
            summary = chat_service.get_chat_summary(chat_session)
            
            return Response({
                'chat_session_id': str(chat_session.id),
                'summary': summary
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def by_remediation(self, request):
        """
        Get all chat sessions for a specific remediation
        GET /api/chat/by_remediation/?remediation_id=uuid
        """
        remediation_id = request.query_params.get('remediation_id')
        if not remediation_id:
            return Response(
                {'error': 'remediation_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        chat_sessions = self.queryset.filter(remediation_id=remediation_id)
        serializer = self.get_serializer(chat_sessions, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def all_history(self, request):
        """
        Get all chat history across all remediations with pagination
        GET /api/chat/all_history/
        
        Optional query parameters:
        - is_active: filter by active status (true/false)
        - remediation_id: filter by specific remediation
        - vulnerability_id: filter by specific vulnerability
        - page: page number
        - page_size: items per page (default: 20)
        - include_messages: include all messages in response (true/false, default: false)
        """
        queryset = self.queryset.select_related(
            'remediation__vulnerability__asset'
        ).prefetch_related('messages')
        
        # Apply filters
        is_active = request.query_params.get('is_active')
        if is_active is not None:
            is_active_bool = is_active.lower() == 'true'
            queryset = queryset.filter(is_active=is_active_bool)
        
        remediation_id = request.query_params.get('remediation_id')
        if remediation_id:
            queryset = queryset.filter(remediation_id=remediation_id)
        
        vulnerability_id = request.query_params.get('vulnerability_id')
        if vulnerability_id:
            queryset = queryset.filter(remediation__vulnerability_id=vulnerability_id)
        
        # Ordering
        ordering = request.query_params.get('ordering', '-updated_at')
        queryset = queryset.order_by(ordering)
        
        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def all_messages(self, request):
        """
        Get all chat messages across all remediations
        GET /api/chat/all_messages/
        
        Optional query parameters:
        - role: filter by role (user/assistant/system)
        - remediation_id: filter by remediation
        - chat_session_id: filter by chat session
        - search: search in message content
        - page: page number
        - page_size: items per page (default: 50)
        """
        
        queryset = ChatMessage.objects.select_related(
            'chat_session__remediation__vulnerability'
        ).all()
        
        # Apply filters
        role = request.query_params.get('role')
        if role:
            queryset = queryset.filter(role=role)
        
        remediation_id = request.query_params.get('remediation_id')
        if remediation_id:
            queryset = queryset.filter(chat_session__remediation_id=remediation_id)
        
        chat_session_id = request.query_params.get('chat_session_id')
        if chat_session_id:
            queryset = queryset.filter(chat_session_id=chat_session_id)
        
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(content__icontains=search)
        
        # Ordering
        queryset = queryset.order_by('-created_at')
        
        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ChatMessageSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = ChatMessageSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """
        Get statistics about chat sessions
        GET /api/chat/statistics/
        """
        
        total_sessions = RemediationChat.objects.count()
        active_sessions = RemediationChat.objects.filter(is_active=True).count()
        
        total_messages = ChatMessage.objects.count()
        user_messages = ChatMessage.objects.filter(role='user').count()
        assistant_messages = ChatMessage.objects.filter(role='assistant').count()
        
        # Sessions with message counts
        session_stats = RemediationChat.objects.annotate(
            msg_count=Count('messages')
        ).aggregate(
            avg_messages=Avg('msg_count'),
            max_messages=Max('msg_count'),
            min_messages=Min('msg_count')
        )
        
        # Remediations with chat sessions
        remediations_with_chat = AIRemediation.objects.filter(
            chat_sessions__isnull=False
        ).distinct().count()
        
        # Updated remediations from chat
        updated_from_chat = RemediationUpdate.objects.filter(
            chat_session__isnull=False
        ).count()
        
        return Response({
            'total_chat_sessions': total_sessions,
            'active_sessions': active_sessions,
            'inactive_sessions': total_sessions - active_sessions,
            'total_messages': total_messages,
            'user_messages': user_messages,
            'assistant_messages': assistant_messages,
            'average_messages_per_session': round(session_stats['avg_messages'] or 0, 2),
            'max_messages_in_session': session_stats['max_messages'] or 0,
            'min_messages_in_session': session_stats['min_messages'] or 0,
            'remediations_with_chat': remediations_with_chat,
            'remediations_updated_from_chat': updated_from_chat
        })
    
    def get_serializer_class(self):
        if self.action in ['retrieve', 'all_history_detailed']:
            return RemediationChatDetailSerializer
        return RemediationChatSerializer

    @action(detail=False, methods=['get'])
    def all_history_detailed(self, request):
        """
        Get detailed chat history with full context
        GET /api/chat/all_history_detailed/
        """
        queryset = self.queryset.select_related(
            'remediation__vulnerability__asset',
            'remediation__vulnerability__asset__organization'
        ).prefetch_related(
            'messages',
            'remediation__updates'
        )
        
        # Apply filters (same as all_history)
        is_active = request.query_params.get('is_active')
        if is_active is not None:
            is_active_bool = is_active.lower() == 'true'
            queryset = queryset.filter(is_active=is_active_bool)
        
        remediation_id = request.query_params.get('remediation_id')
        if remediation_id:
            queryset = queryset.filter(remediation_id=remediation_id)
        
        vulnerability_id = request.query_params.get('vulnerability_id')
        if vulnerability_id:
            queryset = queryset.filter(remediation__vulnerability_id=vulnerability_id)
        
        severity = request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(remediation__vulnerability__severity=severity)
        
        asset_id = request.query_params.get('asset_id')
        if asset_id:
            queryset = queryset.filter(remediation__vulnerability__asset_id=asset_id)
        
        # Ordering
        ordering = request.query_params.get('ordering', '-updated_at')
        queryset = queryset.order_by(ordering)
        
        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = RemediationChatDetailSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = RemediationChatDetailSerializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], url_path='export-all')
    def export_all(self, request):
        format_type = request.query_params.get('format', 'json')
        include_system = request.query_params.get('include_system_messages', 'false').lower() == 'true'

        chat_sessions = (
            RemediationChat.objects
            .select_related('remediation__vulnerability__asset')
            .prefetch_related('messages')
            .all()
        )

        # ------------------------------------------------
        #                   JSON EXPORT
        # ------------------------------------------------
        data = []
        for session in chat_sessions:
            data.append({
                "session_id": str(session.session_id),   # JSON stays unchanged
                "remediation_id": str(session.remediation.id),
                "vulnerability": {
                    "id": str(session.remediation.vulnerability.id),
                    "title": session.remediation.vulnerability.control_title,
                    "severity": session.remediation.vulnerability.severity,
                    "category": session.remediation.vulnerability.category,
                },
                "asset": {
                    "id": str(session.remediation.vulnerability.asset.id),
                    "name": session.remediation.vulnerability.asset.name,
                    "type": session.remediation.vulnerability.asset.asset_type,
                },
                "is_active": session.is_active,
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat(),
                "messages": [
                    {
                        "id": str(msg.id),
                        "role": msg.role,
                        "content": msg.content,
                        "created_at": msg.created_at.isoformat(),
                    }
                    for msg in session.messages.all()
                ],
            })

        return Response(data)


class RemediationUpdateViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing remediation update history
    """
    queryset = RemediationUpdate.objects.all()
    serializer_class = RemediationUpdateSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['remediation', 'chat_session']
    ordering = ['-created_at']

    @action(detail=False, methods=['get'])
    def by_remediation(self, request):
        """
        Get all updates for a specific remediation
        GET /api/remediation-updates/by_remediation/?remediation_id=uuid
        """
        remediation_id = request.query_params.get('remediation_id')
        if not remediation_id:
            return Response(
                {'error': 'remediation_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        updates = self.queryset.filter(remediation_id=remediation_id)
        serializer = self.get_serializer(updates, many=True)
        return Response(serializer.data)


class VulnerabilityRiskAssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for vulnerability risk assessments"""
    queryset = VulnerabilityRiskAssessment.objects.all()
    serializer_class = VulnerabilityRiskAssessmentSerializer
    
    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """
        Calculate risk assessment for a vulnerability
        POST /api/vulnerability-risks/calculate/
        {
            "vulnerability_id": "uuid",
            "recalculate": false
        }
        """
        serializer = CalculateVulnerabilityRiskSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        vulnerability_id = serializer.validated_data['vulnerability_id']
        recalculate = serializer.validated_data.get('recalculate', False)
        
        vulnerability = get_object_or_404(Vulnerability, id=vulnerability_id)
        
        # Check if assessment already exists
        existing_assessment = VulnerabilityRiskAssessment.objects.filter(
            vulnerability=vulnerability
        ).first()
        
        if existing_assessment and not recalculate:
            return Response({
                'message': 'Risk assessment already exists. Use recalculate=true to update.',
                'assessment': VulnerabilityRiskAssessmentSerializer(existing_assessment).data
            }, status=status.HTTP_200_OK)
        
        try:
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
                existing_assessment.last_updated = timezone.now()
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
            
            return Response(
                VulnerabilityRiskAssessmentSerializer(assessment).data,
                status=status.HTTP_201_CREATED if not existing_assessment else status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def by_priority(self, request):
        """
        Get vulnerabilities grouped by priority
        GET /api/vulnerability-risks/by_priority/
        """
        
        priority_stats = VulnerabilityRiskAssessment.objects.values(
            'priority'
        ).annotate(
            count=Count('id')
        ).order_by('priority')
        
        return Response(priority_stats)
    
    @action(detail=False, methods=['get'])
    def high_risk(self, request):
        """
        Get high-risk vulnerabilities (score >= 70)
        GET /api/vulnerability-risks/high_risk/?threshold=70
        """
        threshold = int(request.query_params.get('threshold', 70))
        
        high_risk = self.queryset.filter(
            risk_score__gte=threshold
        ).order_by('-risk_score')
        
        serializer = self.get_serializer(high_risk, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def override(self, request, pk=None):
        """
        Manually override a vulnerability risk assessment
        POST /api/vulnerability-risks/{id}/override/
        
        Body:
        {
            "new_risk_score": 95,
            "new_risk_level": "critical",
            "new_priority": "p1_immediate",
            "override_reason": "Active exploitation observed in production",
            "overridden_by": "security.team@company.com"
        }
        """
        from django.utils import timezone
        
        assessment = self.get_object()
        
        # Validate input
        new_risk_score = request.data.get('new_risk_score')
        new_risk_level = request.data.get('new_risk_level')
        new_priority = request.data.get('new_priority')
        override_reason = request.data.get('override_reason')
        overridden_by = request.data.get('overridden_by')
        
        if new_risk_score is None:
            return Response(
                {'error': 'new_risk_score is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not (0 <= new_risk_score <= 100):
            return Response(
                {'error': 'new_risk_score must be between 0 and 100'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not new_risk_level:
            return Response(
                {'error': 'new_risk_level is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_risk_levels = ['critical', 'high', 'medium', 'low', 'informational']
        if new_risk_level not in valid_risk_levels:
            return Response(
                {'error': f'new_risk_level must be one of: {", ".join(valid_risk_levels)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if new_priority:
            valid_priorities = ['p1_immediate', 'p2_urgent', 'p3_high', 'p4_medium', 'p5_low']
            if new_priority not in valid_priorities:
                return Response(
                    {'error': f'new_priority must be one of: {", ".join(valid_priorities)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if not override_reason:
            return Response(
                {'error': 'override_reason is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not overridden_by:
            return Response(
                {'error': 'overridden_by is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store previous values for history
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Update assessment
        assessment.risk_score = new_risk_score
        assessment.risk_level = new_risk_level
        if new_priority:
            assessment.priority = new_priority
        assessment.is_overridden = True
        assessment.override_reason = override_reason
        assessment.overridden_by = overridden_by
        assessment.overridden_at = timezone.now()
        assessment.save()
        
        # Create history record
        from .models import RiskAssessmentHistory
        RiskAssessmentHistory.objects.create(
            assessment_type='vulnerability',
            object_id=assessment.vulnerability.id,
            object_name=assessment.vulnerability.control_title,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason=f'Manual override by {overridden_by}: {override_reason}'
        )
        
        serializer = self.get_serializer(assessment)
        return Response({
            'message': 'Risk assessment overridden successfully',
            'assessment': serializer.data
        }, status=status.HTTP_200_OK)


    @action(detail=True, methods=['post'])
    def remove_override(self, request, pk=None):
        """
        Remove manual override and revert to AI calculation
        POST /api/vulnerability-risks/{id}/remove_override/
        
        Body:
        {
            "reason": "Override no longer needed, reverting to AI assessment"
        }
        """
        assessment = self.get_object()
        
        if not assessment.is_overridden:
            return Response(
                {'error': 'This assessment is not currently overridden'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        reason = request.data.get('reason', 'Override removed')
        
        # Store values before recalculation
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Recalculate with AI
        from .risk_scoring_service import RiskScoringService
        
        try:
            risk_service = RiskScoringService()
            risk_data = risk_service.calculate_vulnerability_risk(assessment.vulnerability)
            
            # Update assessment
            for key, value in risk_data.items():
                setattr(assessment, key, value)
            
            assessment.is_overridden = False
            assessment.override_reason = ''
            assessment.overridden_by = ''
            assessment.overridden_at = None
            assessment.save()
            
            # Create history record
            from .models import RiskAssessmentHistory
            RiskAssessmentHistory.objects.create(
                assessment_type='vulnerability',
                object_id=assessment.vulnerability.id,
                object_name=assessment.vulnerability.control_title,
                previous_risk_score=previous_score,
                new_risk_score=assessment.risk_score,
                previous_risk_level=previous_level,
                new_risk_level=assessment.risk_level,
                change_reason=f'Override removed, reverted to AI calculation: {reason}'
            )
            
            serializer = self.get_serializer(assessment)
            return Response({
                'message': 'Override removed, reverted to AI calculation',
                'assessment': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to recalculate: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AssetRiskAssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for asset risk assessments"""
    queryset = AssetRiskAssessment.objects.all()
    serializer_class = AssetRiskAssessmentSerializer
    
    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """
        Calculate risk assessment for an asset
        POST /api/asset-risks/calculate/
        {
            "asset_id": "uuid",
            "recalculate": false
        }
        """
        serializer = CalculateAssetRiskSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        asset_id = serializer.validated_data['asset_id']
        recalculate = serializer.validated_data.get('recalculate', False)
        
        asset = get_object_or_404(Asset, id=asset_id)
        
        existing_assessment = AssetRiskAssessment.objects.filter(asset=asset).first()
        
        if existing_assessment and not recalculate:
            return Response({
                'message': 'Risk assessment already exists. Use recalculate=true to update.',
                'assessment': AssetRiskAssessmentSerializer(existing_assessment).data
            }, status=status.HTTP_200_OK)
        
        try:
            risk_service = RiskScoringService()
            risk_data = risk_service.calculate_asset_risk(asset)
            
            previous_score = None
            previous_level = None
            
            if existing_assessment:
                previous_score = existing_assessment.risk_score
                previous_level = existing_assessment.risk_level
                
                for key, value in risk_data.items():
                    setattr(existing_assessment, key, value)
                existing_assessment.last_updated = timezone.now()
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
            
            return Response(
                AssetRiskAssessmentSerializer(assessment).data,
                status=status.HTTP_201_CREATED if not existing_assessment else status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def by_organization(self, request):
        """
        Get asset risks for a specific organization
        GET /api/asset-risks/by_organization/?organization_id=uuid
        """
        org_id = request.query_params.get('organization_id')
        if not org_id:
            return Response(
                {'error': 'organization_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        asset_risks = self.queryset.filter(
            asset__organization_id=org_id
        ).order_by('-risk_score')
        
        serializer = self.get_serializer(asset_risks, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def critical_assets(self, request):
        """
        Get critical assets (score >= 80)
        GET /api/asset-risks/critical_assets/?threshold=80
        """
        threshold = int(request.query_params.get('threshold', 80))
        
        critical = self.queryset.filter(
            risk_score__gte=threshold
        ).order_by('-risk_score')
        
        serializer = self.get_serializer(critical, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def override(self, request, pk=None):
        """
        Manually override an asset risk assessment
        POST /api/asset-risks/{id}/override/
        
        Body:
        {
            "new_risk_score": 85,
            "new_risk_level": "high",
            "new_priority": "p2_urgent",
            "override_reason": "Critical business asset, increasing priority",
            "overridden_by": "ciso@company.com"
        }
        """
        from django.utils import timezone
        
        assessment = self.get_object()
        
        # Validate input
        new_risk_score = request.data.get('new_risk_score')
        new_risk_level = request.data.get('new_risk_level')
        new_priority = request.data.get('new_priority')
        override_reason = request.data.get('override_reason')
        overridden_by = request.data.get('overridden_by')
        
        if new_risk_score is None:
            return Response(
                {'error': 'new_risk_score is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not (0 <= new_risk_score <= 100):
            return Response(
                {'error': 'new_risk_score must be between 0 and 100'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not new_risk_level:
            return Response(
                {'error': 'new_risk_level is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_risk_levels = ['critical', 'high', 'medium', 'low', 'none']
        if new_risk_level not in valid_risk_levels:
            return Response(
                {'error': f'new_risk_level must be one of: {", ".join(valid_risk_levels)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if new_priority:
            valid_priorities = ['p1_immediate', 'p2_urgent', 'p3_high', 'p4_medium', 'p5_low', 'none']
            if new_priority not in valid_priorities:
                return Response(
                    {'error': f'new_priority must be one of: {", ".join(valid_priorities)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if not override_reason:
            return Response(
                {'error': 'override_reason is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not overridden_by:
            return Response(
                {'error': 'overridden_by is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store previous values
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Update assessment
        assessment.risk_score = new_risk_score
        assessment.risk_level = new_risk_level
        if new_priority:
            assessment.priority = new_priority
        assessment.is_overridden = True
        assessment.override_reason = override_reason
        assessment.overridden_by = overridden_by
        assessment.overridden_at = timezone.now()
        assessment.save()
        
        # Create history record
        from .models import RiskAssessmentHistory
        RiskAssessmentHistory.objects.create(
            assessment_type='asset',
            object_id=assessment.asset.id,
            object_name=assessment.asset.name,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason=f'Manual override by {overridden_by}: {override_reason}'
        )
        
        serializer = self.get_serializer(assessment)
        return Response({
            'message': 'Risk assessment overridden successfully',
            'assessment': serializer.data
        }, status=status.HTTP_200_OK)


    @action(detail=True, methods=['post'])
    def remove_override(self, request, pk=None):
        """
        Remove manual override and revert to AI calculation
        POST /api/asset-risks/{id}/remove_override/
        """
        assessment = self.get_object()
        
        if not assessment.is_overridden:
            return Response(
                {'error': 'This assessment is not currently overridden'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        reason = request.data.get('reason', 'Override removed')
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Recalculate with AI
        from .risk_scoring_service import RiskScoringService
        
        try:
            risk_service = RiskScoringService()
            risk_data = risk_service.calculate_asset_risk(assessment.asset)
            
            for key, value in risk_data.items():
                setattr(assessment, key, value)
            
            assessment.is_overridden = False
            assessment.override_reason = ''
            assessment.overridden_by = ''
            assessment.overridden_at = None
            assessment.save()
            
            from .models import RiskAssessmentHistory
            RiskAssessmentHistory.objects.create(
                assessment_type='asset',
                object_id=assessment.asset.id,
                object_name=assessment.asset.name,
                previous_risk_score=previous_score,
                new_risk_score=assessment.risk_score,
                previous_risk_level=previous_level,
                new_risk_level=assessment.risk_level,
                change_reason=f'Override removed, reverted to AI calculation: {reason}'
            )
            
            serializer = self.get_serializer(assessment)
            return Response({
                'message': 'Override removed, reverted to AI calculation',
                'assessment': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to recalculate: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OrganizationRiskAssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for organization risk assessments"""
    queryset = OrganizationRiskAssessment.objects.all()
    serializer_class = OrganizationRiskAssessmentSerializer
    
    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """
        Calculate risk assessment for an organization
        POST /api/organization-risks/calculate/
        {
            "organization_id": "uuid",
            "recalculate": false
        }
        """
        serializer = CalculateOrganizationRiskSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        org_id = serializer.validated_data['organization_id']
        recalculate = serializer.validated_data.get('recalculate', False)
        
        organization = get_object_or_404(Organization, id=org_id)
        
        existing_assessment = OrganizationRiskAssessment.objects.filter(
            organization=organization
        ).first()
        
        if existing_assessment and not recalculate:
            return Response({
                'message': 'Risk assessment already exists. Use recalculate=true to update.',
                'assessment': OrganizationRiskAssessmentSerializer(existing_assessment).data
            }, status=status.HTTP_200_OK)
        
        try:
            risk_service = RiskScoringService()
            risk_data = risk_service.calculate_organization_risk(organization)
            
            previous_score = None
            previous_level = None
            
            if existing_assessment:
                previous_score = existing_assessment.risk_score
                previous_level = existing_assessment.risk_level
                
                for key, value in risk_data.items():
                    setattr(existing_assessment, key, value)
                existing_assessment.last_updated = timezone.now()
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
            
            return Response(
                OrganizationRiskAssessmentSerializer(assessment).data,
                status=status.HTTP_201_CREATED if not existing_assessment else status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def risk_comparison(self, request):
        """
        Compare risk scores across all organizations
        GET /api/organization-risks/risk_comparison/
        """
        organizations = self.queryset.all().order_by('-risk_score')
        
        comparison_data = []
        for org_risk in organizations:
            comparison_data.append({
                'organization_id': str(org_risk.organization.id),
                'organization_name': org_risk.organization.name,
                'risk_score': org_risk.risk_score,
                'risk_level': org_risk.risk_level,
                'total_assets': org_risk.asset_summary.get('total_assets', 0),
                'total_vulnerabilities': org_risk.asset_summary.get('total_vulnerabilities', 0)
            })
        
        return Response(comparison_data)
    
    @action(detail=True, methods=['post'])
    def override(self, request, pk=None):
        """
        Manually override an organization risk assessment
        POST /api/organization-risks/{id}/override/
        
        Body:
        {
            "new_risk_score": 75,
            "new_risk_level": "high",
            "override_reason": "Recent security incidents require elevated risk rating",
            "overridden_by": "ciso@company.com"
        }
        """
        from django.utils import timezone
        
        assessment = self.get_object()
        
        # Validate input
        new_risk_score = request.data.get('new_risk_score')
        new_risk_level = request.data.get('new_risk_level')
        override_reason = request.data.get('override_reason')
        overridden_by = request.data.get('overridden_by')
        
        if new_risk_score is None:
            return Response(
                {'error': 'new_risk_score is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not (0 <= new_risk_score <= 100):
            return Response(
                {'error': 'new_risk_score must be between 0 and 100'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not new_risk_level:
            return Response(
                {'error': 'new_risk_level is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_risk_levels = ['critical', 'high', 'medium', 'low', 'none']
        if new_risk_level not in valid_risk_levels:
            return Response(
                {'error': f'new_risk_level must be one of: {", ".join(valid_risk_levels)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not override_reason:
            return Response(
                {'error': 'override_reason is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not overridden_by:
            return Response(
                {'error': 'overridden_by is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store previous values
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Update assessment
        assessment.risk_score = new_risk_score
        assessment.risk_level = new_risk_level
        assessment.is_overridden = True
        assessment.override_reason = override_reason
        assessment.overridden_by = overridden_by
        assessment.overridden_at = timezone.now()
        assessment.save()
        
        # Create history record
        from .models import RiskAssessmentHistory
        RiskAssessmentHistory.objects.create(
            assessment_type='organization',
            object_id=assessment.organization.id,
            object_name=assessment.organization.name,
            previous_risk_score=previous_score,
            new_risk_score=assessment.risk_score,
            previous_risk_level=previous_level,
            new_risk_level=assessment.risk_level,
            change_reason=f'Manual override by {overridden_by}: {override_reason}'
        )
        
        serializer = self.get_serializer(assessment)
        return Response({
            'message': 'Risk assessment overridden successfully',
            'assessment': serializer.data
        }, status=status.HTTP_200_OK)


    @action(detail=True, methods=['post'])
    def remove_override(self, request, pk=None):
        """
        Remove manual override and revert to AI calculation
        POST /api/organization-risks/{id}/remove_override/
        """
        assessment = self.get_object()
        
        if not assessment.is_overridden:
            return Response(
                {'error': 'This assessment is not currently overridden'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        reason = request.data.get('reason', 'Override removed')
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        
        # Recalculate with AI
        from .risk_scoring_service import RiskScoringService
        
        try:
            risk_service = RiskScoringService()
            risk_data = risk_service.calculate_organization_risk(assessment.organization)
            
            for key, value in risk_data.items():
                setattr(assessment, key, value)
            
            assessment.is_overridden = False
            assessment.override_reason = ''
            assessment.overridden_by = ''
            assessment.overridden_at = None
            assessment.save()
            
            from .models import RiskAssessmentHistory
            RiskAssessmentHistory.objects.create(
                assessment_type='organization',
                object_id=assessment.organization.id,
                object_name=assessment.organization.name,
                previous_risk_score=previous_score,
                new_risk_score=assessment.risk_score,
                previous_risk_level=previous_level,
                new_risk_level=assessment.risk_level,
                change_reason=f'Override removed, reverted to AI calculation: {reason}'
            )
            
            serializer = self.get_serializer(assessment)
            return Response({
                'message': 'Override removed, reverted to AI calculation',
                'assessment': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to recalculate: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RiskAssessmentHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for risk assessment history"""
    queryset = RiskAssessmentHistory.objects.all()
    serializer_class = RiskAssessmentHistorySerializer
    
    @action(detail=False, methods=['get'])
    def by_object(self, request):
        """
        Get risk history for a specific object
        GET /api/risk-history/by_object/?object_id=uuid&type=vulnerability
        """
        object_id = request.query_params.get('object_id')
        assessment_type = request.query_params.get('type')
        
        if not object_id or not assessment_type:
            return Response(
                {'error': 'object_id and type parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        history = self.queryset.filter(
            object_id=object_id,
            assessment_type=assessment_type
        ).order_by('-created_at')
        
        serializer = self.get_serializer(history, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def trending_risks(self, request):
        """
        Get objects with increasing risk trends
        GET /api/risk-history/trending_risks/?days=30
        """
        
        days = int(request.query_params.get('days', 30))
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Get objects with multiple assessments
        trending = self.queryset.filter(
            created_at__gte=cutoff_date
        ).values('object_id', 'object_name', 'assessment_type').annotate(
            assessment_count=Count('id'),
            avg_change=Avg('new_risk_score') - Avg('previous_risk_score')
        ).filter(
            assessment_count__gte=2
        ).order_by('-avg_change')
        
        return Response(trending)


# Add these actions to existing viewsets

# Add to VulnerabilityViewSet
@action(detail=True, methods=['get'])
def with_risk(self, request, pk=None):
    """
    Get vulnerability with risk assessment
    GET /api/vulnerabilities/{id}/with_risk/
    """
    vulnerability = self.get_object()
    serializer = VulnerabilityWithRiskSerializer(vulnerability)
    return Response(serializer.data)


# Add to AssetViewSet
@action(detail=True, methods=['get'])
def with_risk(self, request, pk=None):
    """
    Get asset with risk assessment
    GET /api/assets/{id}/with_risk/
    """
    asset = self.get_object()
    serializer = AssetWithRiskSerializer(asset)
    return Response(serializer.data)


# Add to OrganizationViewSet
@action(detail=True, methods=['get'])
def with_risk(self, request, pk=None):
    """
    Get organization with risk assessment
    GET /api/organizations/{id}/with_risk/
    """
    organization = self.get_object()
    serializer = OrganizationWithRiskSerializer(organization)
    return Response(serializer.data)


# Bulk operations viewset
class BulkRiskCalculationViewSet(viewsets.ViewSet):
    """ViewSet for bulk risk calculation operations"""
    
    @action(detail=False, methods=['post'])
    def calculate_all(self, request):
        """
        Bulk calculate risk assessments
        POST /api/bulk-risk/calculate_all/
        {
            "scope": "all_vulnerabilities",  // or "all_assets", "all_organizations", "organization", "asset"
            "object_id": "uuid",  // required for "organization" or "asset" scope
            "recalculate_existing": false
        }
        """
        serializer = BulkRiskCalculationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scope = serializer.validated_data['scope']
        object_id = serializer.validated_data.get('object_id')
        recalculate = serializer.validated_data.get('recalculate_existing', False)
        
        risk_service = RiskScoringService()
        results = {
            'vulnerabilities_processed': 0,
            'assets_processed': 0,
            'organizations_processed': 0,
            'errors': []
        }
        
        try:
            if scope == 'all_vulnerabilities':
                vulnerabilities = Vulnerability.objects.all()
                if not recalculate:
                    vulnerabilities = vulnerabilities.filter(risk_assessment__isnull=True)
                
                for vuln in vulnerabilities:
                    try:
                        risk_data = risk_service.calculate_vulnerability_risk(vuln)
                        VulnerabilityRiskAssessment.objects.update_or_create(
                            vulnerability=vuln,
                            defaults=risk_data
                        )
                        results['vulnerabilities_processed'] += 1
                    except Exception as e:
                        results['errors'].append(f"Vulnerability {vuln.id}: {str(e)}")
            
            elif scope == 'all_assets':
                assets = Asset.objects.all()
                if not recalculate:
                    assets = assets.filter(risk_assessment__isnull=True)
                
                for asset in assets:
                    try:
                        risk_data = risk_service.calculate_asset_risk(asset)
                        AssetRiskAssessment.objects.update_or_create(
                            asset=asset,
                            defaults=risk_data
                        )
                        results['assets_processed'] += 1
                    except Exception as e:
                        results['errors'].append(f"Asset {asset.id}: {str(e)}")
            
            elif scope == 'all_organizations':
                organizations = Organization.objects.all()
                if not recalculate:
                    organizations = organizations.filter(risk_assessment__isnull=True)
                
                for org in organizations:
                    try:
                        risk_data = risk_service.calculate_organization_risk(org)
                        OrganizationRiskAssessment.objects.update_or_create(
                            organization=org,
                            defaults=risk_data
                        )
                        results['organizations_processed'] += 1
                    except Exception as e:
                        results['errors'].append(f"Organization {org.id}: {str(e)}")
            
            elif scope == 'organization' and object_id:
                organization = get_object_or_404(Organization, id=object_id)
                
                # Calculate for all assets in organization
                for asset in organization.assets.all():
                    try:
                        risk_data = risk_service.calculate_asset_risk(asset)
                        AssetRiskAssessment.objects.update_or_create(
                            asset=asset,
                            defaults=risk_data
                        )
                        results['assets_processed'] += 1
                    except Exception as e:
                        results['errors'].append(f"Asset {asset.id}: {str(e)}")
                
                # Calculate organization risk
                try:
                    risk_data = risk_service.calculate_organization_risk(organization)
                    OrganizationRiskAssessment.objects.update_or_create(
                        organization=organization,
                        defaults=risk_data
                    )
                    results['organizations_processed'] += 1
                except Exception as e:
                    results['errors'].append(f"Organization {organization.id}: {str(e)}")
            
            elif scope == 'asset' and object_id:
                asset = get_object_or_404(Asset, id=object_id)
                
                # Calculate for all vulnerabilities in asset
                for vuln in asset.vulnerabilities.all():
                    try:
                        risk_data = risk_service.calculate_vulnerability_risk(vuln)
                        VulnerabilityRiskAssessment.objects.update_or_create(
                            vulnerability=vuln,
                            defaults=risk_data
                        )
                        results['vulnerabilities_processed'] += 1
                    except Exception as e:
                        results['errors'].append(f"Vulnerability {vuln.id}: {str(e)}")
                
                # Calculate asset risk
                try:
                    risk_data = risk_service.calculate_asset_risk(asset)
                    AssetRiskAssessment.objects.update_or_create(
                        asset=asset,
                        defaults=risk_data
                    )
                    results['assets_processed'] += 1
                except Exception as e:
                    results['errors'].append(f"Asset {asset.id}: {str(e)}")
            
            return Response(results, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )