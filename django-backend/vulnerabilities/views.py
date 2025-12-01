# ---------------------------------
# Standard Library
# ---------------------------------
from datetime import timedelta
import json

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
    RiskContext,
    RiskOverrideHistory,
    RiskContextChat,
    RiskContextChatMessage
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
    RiskContextSerializer,
    AddRiskContextSerializer,
    RemoveRiskContextSerializer,
    RiskOverrideHistorySerializer,
    ManualOverrideSerializer,
    RevertToStateSerializer,
    RiskContextChatSerializer,
    RiskContextChatMessageSerializer,
    ApplyContextToSimilarSerializer,
    EnhancedVulnerabilityRiskAssessmentSerializer,
    VulnerabilityWithAssetDetailsSerializer
)

# ---------------------------------
# Local App - Services & Tasks
# ---------------------------------
from .ai_service import AIRemediationService
from .chat_service import RemediationChatService
from .risk_scoring_service import RiskScoringService
from .tasks import generate_remediation_task, process_feedback_task
from .risk_context_service import RiskContextService


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
            return VulnerabilityWithAssetDetailsSerializer
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
    UPDATED: Store both positive and negative feedback in Vector DB
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
                'feedback_id': str(feedback.id),
                'feedback_type': 'positive' if was_helpful else 'negative'
            }, status=status.HTTP_202_ACCEPTED)
        else:
            # Synchronous processing
            try:
                ai_service = AIRemediationService()
                vector_id, success_vector_id = ai_service.process_feedback(
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
                return Response({
                    **response_serializer.data,
                    'feedback_type': 'positive' if was_helpful else 'negative',
                    'vector_db_stored': True,
                    'feedback_vector_id': vector_id,
                    'success_vector_id': success_vector_id
                }, status=status.HTTP_201_CREATED)

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


class RiskContextViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing risk contexts
    Context additions influence AI risk calculation without direct override
    """
    queryset = RiskContext.objects.all()
    serializer_class = RiskContextSerializer

    @action(detail=False, methods=['post'])
    def add_context(self, request):
        """
        Add context to a risk assessment and recalculate

        POST /api/risk-contexts/add_context/
        {
            "context_type": "vulnerability",
            "object_id": "uuid",
            "context_text": "This system handles sensitive PII data",
            "added_by": "user@example.com"
        }
        """
        serializer = AddRiskContextSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        context_service = RiskContextService()

        try:
            result = context_service.add_context_and_recalculate(
                context_type=serializer.validated_data['context_type'],
                object_id=serializer.validated_data['object_id'],
                context_text=serializer.validated_data['context_text'],
                added_by=serializer.validated_data['added_by']
            )

            # Check for similar vulnerabilities if this is a vulnerability context
            similar_vulnerabilities = []
            chat_session = None

            if serializer.validated_data['context_type'] == 'vulnerability':
                similar_vulnerabilities = context_service.find_similar_vulnerabilities(
                    result['context_record']
                )

                if similar_vulnerabilities:
                    # Start a chat session to ask about applying to similar vulns
                    chat_session = context_service.start_context_application_chat(
                        result['context_record'],
                        similar_vulnerabilities
                    )

            response_data = {
                'context': RiskContextSerializer(result['context_record']).data,
                'updated_risk_score': result['risk_data']['risk_score'],
                'updated_risk_level': result['risk_data']['risk_level'],
                'updated_priority': result['risk_data']['priority'],
                'reasoning': result['risk_data']['reasoning']
            }

            if chat_session:
                response_data['similar_vulnerabilities_found'] = len(similar_vulnerabilities)
                response_data['chat_session_id'] = str(chat_session.id)
                response_data['message'] = 'Context added and similar vulnerabilities found. Check the chat session for suggestions.'

            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def remove_context(self, request, pk=None):
        """
        Remove a context and recalculate risk without it

        POST /api/risk-contexts/{id}/remove_context/
        """
        context = self.get_object()

        if not context.is_active:
            return Response(
                {'error': 'This context is already inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        context_service = RiskContextService()

        try:
            updated_assessment = context_service.remove_context_and_recalculate(
                context.id
            )

            return Response({
                'message': 'Context removed and risk recalculated',
                'updated_risk_score': updated_assessment.risk_score,
                'updated_risk_level': updated_assessment.risk_level,
                'updated_priority': updated_assessment.priority
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def by_object(self, request):
        """
        Get all contexts for a specific object

        GET /api/risk-contexts/by_object/?object_id=uuid&type=vulnerability
        """
        object_id = request.query_params.get('object_id')
        context_type = request.query_params.get('type')

        if not object_id or not context_type:
            return Response(
                {'error': 'object_id and type parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        contexts = self.queryset.filter(
            context_type=context_type,
            object_id=object_id,
            is_active=True
        ).order_by('-added_at')

        serializer = self.get_serializer(contexts, many=True)
        return Response(serializer.data)


class RiskOverrideViewSet(viewsets.ModelViewSet):
    """
    ViewSet for manual risk overrides with full history tracking
    """
    queryset = RiskOverrideHistory.objects.all()
    serializer_class = RiskOverrideHistorySerializer

    @action(detail=False, methods=['post'])
    def manual_override(self, request):
        """
        Manually override risk score, level, and priority
        This is used when user is not satisfied with AI + context calculation

        POST /api/risk-overrides/manual_override/
        {
            "override_type": "vulnerability",
            "object_id": "uuid",
            "new_risk_score": 85,
            "new_risk_level": "high",
            "new_priority": "p2_urgent",
            "reason": "Executive decision: this is critical infrastructure",
            "performed_by": "ciso@example.com"
        }
        """
        serializer = ManualOverrideSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        override_type = serializer.validated_data['override_type']
        object_id = serializer.validated_data['object_id']

        # Get current assessment
        if override_type == 'vulnerability':
            from .models import Vulnerability
            obj = get_object_or_404(Vulnerability, id=object_id)
            assessment = get_object_or_404(
                VulnerabilityRiskAssessment,
                vulnerability=obj
            )
        elif override_type == 'asset':
            from .models import Asset
            obj = get_object_or_404(Asset, id=object_id)
            assessment = get_object_or_404(AssetRiskAssessment, asset=obj)
        else:
            from .models import Organization
            obj = get_object_or_404(Organization, id=object_id)
            assessment = get_object_or_404(
                OrganizationRiskAssessment,
                organization=obj
            )

        # Mark all previous overrides as not current
        RiskOverrideHistory.objects.filter(
            override_type=override_type,
            object_id=object_id,
            is_current_state=True
        ).update(is_current_state=False)

        # Create override history record
        override_history = RiskOverrideHistory.objects.create(
            override_type=override_type,
            object_id=object_id,
            action='override',
            previous_risk_score=assessment.risk_score,
            previous_risk_level=assessment.risk_level,
            previous_priority=assessment.priority,
            new_risk_score=serializer.validated_data['new_risk_score'],
            new_risk_level=serializer.validated_data['new_risk_level'],
            new_priority=serializer.validated_data['new_priority'],
            reason=serializer.validated_data['reason'],
            performed_by=serializer.validated_data['performed_by'],
            is_current_state=True
        )

        # Update assessment
        assessment.risk_score = serializer.validated_data['new_risk_score']
        assessment.risk_level = serializer.validated_data['new_risk_level']
        assessment.priority = serializer.validated_data['new_priority']
        assessment.has_manual_override = True
        assessment.current_override_id = override_history.id
        assessment.save()

        return Response({
            'message': 'Risk manually overridden',
            'override_history': RiskOverrideHistorySerializer(override_history).data,
            'updated_assessment': {
                'risk_score': assessment.risk_score,
                'risk_level': assessment.risk_level,
                'priority': assessment.priority
            }
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def revert_to_state(self, request):
        """
        Revert to any previous state in override history

        POST /api/risk-overrides/revert_to_state/
        {
            "override_history_id": "uuid",
            "reason": "Reverting to state before last override",
            "performed_by": "user@example.com"
        }
        """
        serializer = RevertToStateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        target_state = get_object_or_404(
            RiskOverrideHistory,
            id=serializer.validated_data['override_history_id']
        )

        override_type = target_state.override_type
        object_id = target_state.object_id

        # Get current assessment
        if override_type == 'vulnerability':
            from .models import Vulnerability
            obj = get_object_or_404(Vulnerability, id=object_id)
            assessment = get_object_or_404(
                VulnerabilityRiskAssessment,
                vulnerability=obj
            )
        elif override_type == 'asset':
            from .models import Asset
            obj = get_object_or_404(Asset, id=object_id)
            assessment = get_object_or_404(AssetRiskAssessment, asset=obj)
        else:
            from .models import Organization
            obj = get_object_or_404(Organization, id=object_id)
            assessment = get_object_or_404(
                OrganizationRiskAssessment,
                organization=obj
            )

        # Mark all as not current
        RiskOverrideHistory.objects.filter(
            override_type=override_type,
            object_id=object_id,
            is_current_state=True
        ).update(is_current_state=False)

        # Create revert history record
        revert_history = RiskOverrideHistory.objects.create(
            override_type=override_type,
            object_id=object_id,
            action='revert',
            previous_risk_score=assessment.risk_score,
            previous_risk_level=assessment.risk_level,
            previous_priority=assessment.priority,
            new_risk_score=target_state.new_risk_score,
            new_risk_level=target_state.new_risk_level,
            new_priority=target_state.new_priority,
            reason=serializer.validated_data['reason'],
            performed_by=serializer.validated_data['performed_by'],
            is_current_state=True
        )

        # Update assessment to target state
        assessment.risk_score = target_state.new_risk_score
        assessment.risk_level = target_state.new_risk_level
        assessment.priority = target_state.new_priority
        assessment.current_override_id = revert_history.id
        assessment.save()

        return Response({
            'message': f'Reverted to state from {target_state.performed_at}',
            'revert_history': RiskOverrideHistorySerializer(revert_history).data,
            'updated_assessment': {
                'risk_score': assessment.risk_score,
                'risk_level': assessment.risk_level,
                'priority': assessment.priority
            }
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def history(self, request):
        """
        Get override history for an object

        GET /api/risk-overrides/history/?object_id=uuid&type=vulnerability
        """
        object_id = request.query_params.get('object_id')
        override_type = request.query_params.get('type')

        if not object_id or not override_type:
            return Response(
                {'error': 'object_id and type parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        history = self.queryset.filter(
            override_type=override_type,
            object_id=object_id
        ).order_by('-performed_at')

        serializer = self.get_serializer(history, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def remove_all_overrides(self, request):
        """
        Remove all manual overrides and revert to AI + context calculation

        POST /api/risk-overrides/remove_all_overrides/
        {
            "override_type": "vulnerability",
            "object_id": "uuid",
            "reason": "Reverting to AI calculation",
            "performed_by": "user@example.com"
        }
        """
        override_type = request.data.get('override_type')
        object_id = request.data.get('object_id')
        reason = request.data.get('reason')
        performed_by = request.data.get('performed_by')

        if not all([override_type, object_id, reason, performed_by]):
            return Response(
                {'error': 'All fields are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get current assessment
        if override_type == 'vulnerability':
            from .models import Vulnerability
            obj = get_object_or_404(Vulnerability, id=object_id)
            assessment = get_object_or_404(
                VulnerabilityRiskAssessment,
                vulnerability=obj
            )
        elif override_type == 'asset':
            from .models import Asset
            obj = get_object_or_404(Asset, id=object_id)
            assessment = get_object_or_404(AssetRiskAssessment, asset=obj)
        else:
            from .models import Organization
            obj = get_object_or_404(Organization, id=object_id)
            assessment = get_object_or_404(
                OrganizationRiskAssessment,
                organization=obj
            )

        # Recalculate with contexts
        context_service = RiskContextService()

        # Get active contexts
        active_contexts = RiskContext.objects.filter(
            context_type=override_type,
            object_id=object_id,
            is_active=True
        ).order_by('added_at')

        if active_contexts.exists():
            # Recalculate with contexts
            combined_context = "\n\n".join([
                ctx.context_text for ctx in active_contexts
            ])
            new_risk_data = context_service._recalculate_with_context(
                override_type,
                obj,
                assessment,
                combined_context
            )
        else:
            # Recalculate base risk
            from .risk_scoring_service import RiskScoringService
            risk_service = RiskScoringService()

            if override_type == 'vulnerability':
                new_risk_data = risk_service.calculate_vulnerability_risk(obj)
            elif override_type == 'asset':
                new_risk_data = risk_service.calculate_asset_risk(obj)
            else:
                new_risk_data = risk_service.calculate_organization_risk(obj)

        # Mark all overrides as not current
        RiskOverrideHistory.objects.filter(
            override_type=override_type,
            object_id=object_id,
            is_current_state=True
        ).update(is_current_state=False)

        # Update assessment
        previous_score = assessment.risk_score
        previous_level = assessment.risk_level
        previous_priority = assessment.priority

        for key, value in new_risk_data.items():
            setattr(assessment, key, value)

        assessment.has_manual_override = False
        assessment.current_override_id = None
        assessment.save()

        return Response({
            'message': 'All overrides removed, reverted to AI calculation',
            'previous': {
                'risk_score': previous_score,
                'risk_level': previous_level,
                'priority': previous_priority
            },
            'updated': {
                'risk_score': assessment.risk_score,
                'risk_level': assessment.risk_level,
                'priority': assessment.priority
            }
        }, status=status.HTTP_200_OK)


class RiskContextChatViewSet(viewsets.ModelViewSet):
    """
    ViewSet for risk context chat sessions
    Handles applying context to similar vulnerabilities
    """
    queryset = RiskContextChat.objects.all()
    serializer_class = RiskContextChatSerializer

    @action(detail=True, methods=['post'])
    def send_message(self, request, pk=None):
        """
        Send a message in the context chat
        AI analyzes the message and returns specific vulnerability IDs based on user intent

        POST /api/risk-context-chats/{id}/send_message/
        {
            "message": "Yes, apply to all" or "High confidence only" or "Apply to ID1 and ID2"
        }

        Response includes:
        - Detected intent (approve_all, approve_high_confidence, approve_specific, etc.)
        - Specific vulnerability IDs to apply to
        - User-friendly confirmation message
        """
        chat_session = self.get_object()
        message = request.data.get('message')

        if not message:
            return Response(
                {'error': 'message is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Save user message
        user_msg = RiskContextChatMessage.objects.create(
            chat_session=chat_session,
            role='user',
            content=message
        )

        # Process user intent with AI
        context_service = RiskContextService()

        try:
            intent_response = context_service.process_user_chat_response(
                chat_session,
                message
            )

            # Update chat session with detected intent
            chat_session.detected_intent = intent_response['intent']
            chat_session.intent_confidence = intent_response['confidence']
            chat_session.save()

            # Create assistant response with detailed information
            assistant_content = intent_response['user_friendly_message']

            assistant_msg = RiskContextChatMessage.objects.create(
                chat_session=chat_session,
                role='assistant',
                content=assistant_content
            )

            # Get all messages
            messages = RiskContextChatMessage.objects.filter(
                chat_session=chat_session
            ).order_by('created_at')

            return Response({
                'intent': intent_response['intent'],
                'intent_confidence': intent_response['confidence'],
                'vulnerability_ids': intent_response['vulnerability_ids'],
                'reasoning': intent_response['reasoning'],
                'messages': RiskContextChatMessageSerializer(messages, many=True).data,
                'ready_to_apply': intent_response['intent'] in [
                    'approve_all', 'approve_high_confidence', 'approve_specific'
                ],
                'next_steps': self._get_next_steps_instructions(
                    intent_response['intent'],
                    str(chat_session.id),
                    intent_response['vulnerability_ids'],
                    request
                )
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_next_steps_instructions(self, intent, chat_session_id, vuln_ids, request):
        """Generate next steps instructions based on intent"""

        if intent == 'decline':
            return {
                'action': 'none',
                'message': 'Context application cancelled. The context remains only on the original vulnerability.'
            }

        if intent == 'need_more_info':
            return {
                'action': 'provide_details',
                'message': 'Please ask your follow-up questions or say "yes" to proceed with application.'
            }

        # For approval intents
        return {
            'action': 'call_apply_endpoint',
            'endpoint': f'/api/risk-context-chats/{chat_session_id}/apply_to_similar/',
            'method': 'POST',
            'body': {
                'approved': True,
                'selected_vulnerability_ids': vuln_ids
            },
            'curl_example': f'''curl -X POST "{request.build_absolute_uri(f'/api/risk-context-chats/{chat_session_id}/apply_to_similar/')}" \\
  -H "Content-Type: application/json" \\
  -d '{{"approved": true, "selected_vulnerability_ids": {json.dumps(vuln_ids)}}}'
''',
            'message': f'Ready to apply context to {len(vuln_ids)} vulnerabilities. Call the apply endpoint to proceed.'
        }

    @action(detail=True, methods=['post'])
    def apply_to_similar(self, request, pk=None):
        """
        Apply context to similar vulnerabilities based on user decision

        POST /api/risk-context-chats/{id}/apply_to_similar/
        {
            "approved": true,
            "selected_vulnerability_ids": ["uuid1", "uuid2"],  // optional
            "user_message": "Apply to high confidence matches only"  // optional
        }
        """
        chat_session = self.get_object()
        serializer = ApplyContextToSimilarSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        context_service = RiskContextService()

        try:
            result = context_service.apply_context_to_similar_vulnerabilities(
                chat_session,
                serializer.validated_data['approved'],
                serializer.validated_data.get('selected_vulnerability_ids')
            )

            # Save user response if provided
            user_message = serializer.validated_data.get('user_message')
            if user_message:
                chat_session.user_response = user_message
                chat_session.save()

            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def active_suggestions(self, request):
        """
        Get all active context application suggestions

        GET /api/risk-context-chats/active_suggestions/
        """
        active_chats = self.queryset.filter(is_active=True)
        serializer = self.get_serializer(active_chats, many=True)
        return Response(serializer.data)