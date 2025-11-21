from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    OrganizationViewSet,
    AssetViewSet,
    VulnerabilityViewSet,
    TesterArtifactViewSet,
    AIRemediationViewSet,
    RemediationFeedbackViewSet
)

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'assets', AssetViewSet, basename='asset')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'artifacts', TesterArtifactViewSet, basename='artifact')
router.register(r'remediations', AIRemediationViewSet, basename='remediation')
router.register(r'feedback', RemediationFeedbackViewSet, basename='feedback')

urlpatterns = [
    path('', include(router.urls)),
]