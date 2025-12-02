from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    OrganizationViewSet,
    AssetViewSet,
    VulnerabilityViewSet,
    TesterArtifactViewSet,
    AIRemediationViewSet,
    RemediationFeedbackViewSet,
    RemediationChatViewSet,
    RemediationUpdateViewSet,
    VulnerabilityRiskAssessmentViewSet,
    AssetRiskAssessmentViewSet,
    OrganizationRiskAssessmentViewSet,
    RiskAssessmentHistoryViewSet,
    BulkRiskCalculationViewSet,
    RiskContextViewSet,
    RiskOverrideViewSet,
    RiskContextChatViewSet,
    GlobalChatbotViewSet
)

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'assets', AssetViewSet, basename='asset')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'artifacts', TesterArtifactViewSet, basename='artifact')
router.register(r'remediations', AIRemediationViewSet, basename='remediation')
router.register(r'feedback', RemediationFeedbackViewSet, basename='feedback')
router.register(r'chat', RemediationChatViewSet, basename='chat')
router.register(r'remediation-updates', RemediationUpdateViewSet, basename='remediation-update')
router.register(r'vulnerability-risks', VulnerabilityRiskAssessmentViewSet, basename='vulnerability-risk')
router.register(r'asset-risks', AssetRiskAssessmentViewSet, basename='asset-risk')
router.register(r'organization-risks', OrganizationRiskAssessmentViewSet, basename='organization-risk')
router.register(r'risk-history', RiskAssessmentHistoryViewSet, basename='risk-history')
router.register(r'bulk-risk', BulkRiskCalculationViewSet, basename='bulk-risk')
router.register(r'risk-contexts', RiskContextViewSet, basename='risk-context')
router.register(r'risk-overrides', RiskOverrideViewSet, basename='risk-override')
router.register(r'risk-context-chats', RiskContextChatViewSet, basename='risk-context-chat')
router.register(r'chatbot', GlobalChatbotViewSet, basename='chatbot')

urlpatterns = [
    path('', include(router.urls)),
]