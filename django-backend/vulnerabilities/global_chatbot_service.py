"""
Global Chatbot Service - AI-powered analytics and insights
Provides natural language querying with auto-suggestions and visualizations
"""
from django.conf import settings
from openai import OpenAI
import json
from datetime import datetime, timedelta, date
from django.db.models import Count, Q, Avg
from uuid import UUID
from decimal import Decimal
from .models import (
    Organization, Asset, Vulnerability, 
    VulnerabilityRiskAssessment, AssetRiskAssessment,
    OrganizationRiskAssessment, AIRemediation
)

client = OpenAI(api_key=settings.OPENAI_API_KEY)


class UUIDEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles UUIDs, dates, and decimals"""
    def default(self, obj):
        if isinstance(obj, UUID):
            return str(obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, timedelta):
            return str(obj)
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def convert_uuids_to_strings(obj):
    """Recursively convert UUID objects to strings in dictionaries and lists"""
    if isinstance(obj, UUID):
        return str(obj)
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, timedelta):
        return str(obj)
    elif isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {key: convert_uuids_to_strings(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_uuids_to_strings(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_uuids_to_strings(item) for item in obj)
    else:
        return obj


class GlobalChatbotService:
    """Service for global AI chatbot with analytics and insights"""
    
    def __init__(self):
        self.model = "gpt-4o-mini"
        
    def get_question_suggestions(self, partial_query):
        """
        Get AI-powered question suggestions as user types
        
        Args:
            partial_query: The text user has typed so far
            
        Returns:
            List of suggested complete questions
        """
        
        # Get current system statistics for context
        stats = self._get_system_statistics()
        
        prompt = f"""Based on the user's partial query and available data, suggest 5 relevant complete questions they might want to ask.

USER'S PARTIAL QUERY: "{partial_query}"

AVAILABLE DATA CONTEXT:
- Total Organizations: {stats['total_organizations']}
- Total Assets: {stats['total_assets']}
- Total Vulnerabilities: {stats['total_vulnerabilities']}
- Critical Vulnerabilities: {stats['critical_vulnerabilities']}
- High Risk Assets: {stats['high_risk_assets']}

EXAMPLE QUESTIONS USERS CAN ASK:
- "How many assets have high vulnerabilities?"
- "Tell me how many common vulnerabilities exist on an asset"
- "Tell me how many critical issues were highlighted in [asset name] in past 3 years"
- "What are the top 5 most vulnerable assets?"
- "Show me the trend of vulnerabilities over the past 6 months"
- "Which assets have unresolved critical vulnerabilities?"
- "Compare vulnerability severity across all assets"
- "What percentage of vulnerabilities have AI remediations?"
- "Show me assets with the most OWASP Top 10 vulnerabilities"
- "Which organization has the highest risk score?"

Return ONLY a JSON array of 5 suggested complete questions that:
1. Complete or extend the user's partial query
2. Are relevant to available data
3. Can be answered with the existing data
4. Are specific and actionable

Format:
{{
  "suggestions": [
    "Complete question 1",
    "Complete question 2",
    "Complete question 3",
    "Complete question 4",
    "Complete question 5"
  ]
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a helpful assistant suggesting questions about cybersecurity vulnerability data. Return only valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=500,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get('suggestions', [])
            
        except Exception as e:
            print(f"Error getting suggestions: {str(e)}")
            return []
    
    def process_query(self, user_query, organization_id=None):
        """
        Process user's natural language query and return answer with visualizations
        
        Args:
            user_query: Natural language question from user
            organization_id: Optional - filter data by organization
            
        Returns:
            Dict with answer, data for visualization, and chart configuration
        """
        
        # Get system statistics
        stats = self._get_comprehensive_statistics(organization_id)
        
        # Analyze query intent and extract data
        query_analysis = self._analyze_query(user_query, stats)
        
        # Fetch relevant data based on intent
        data_result = self._fetch_data_for_query(query_analysis, organization_id)
        
        # Convert all UUIDs to strings
        data_result = convert_uuids_to_strings(data_result)
        stats = convert_uuids_to_strings(stats)
        query_analysis = convert_uuids_to_strings(query_analysis)
        
        # Generate natural language answer
        answer = self._generate_answer(user_query, query_analysis, data_result, stats)
        
        # Final cleanup of any remaining UUIDs
        answer = convert_uuids_to_strings(answer)
        
        return answer
    
    def _analyze_query(self, user_query, stats):
        """
        Use AI to analyze user query and determine intent, entities, and time range
        """
        
        prompt = f"""Analyze this user query about cybersecurity vulnerabilities and extract:
1. Intent (what they want to know)
2. Entities mentioned (asset names, organization names, vulnerability types)
3. Time range (if mentioned)
4. Metrics needed
5. Whether visualization is needed
6. Recommended chart type if visualization needed

USER QUERY: "{user_query}"

AVAILABLE DATA SUMMARY:
{json.dumps(stats, indent=2)}

Return JSON with:
{{
  "intent": "description of what user wants",
  "query_type": "count|comparison|trend|ranking|distribution|detail",
  "entities": {{
    "assets": ["asset names mentioned"],
    "organizations": ["org names mentioned"],
    "severities": ["critical", "high", etc],
    "categories": ["SQL Injection", etc]
  }},
  "time_range": {{
    "specified": true/false,
    "period": "3 months|6 months|1 year|all time",
    "start_date": "YYYY-MM-DD or null",
    "end_date": "YYYY-MM-DD or null"
  }},
  "metrics": ["vulnerability_count", "risk_score", "asset_count", etc],
  "needs_visualization": true/false,
  "chart_type": "bar|line|pie|table|multi-series" or null,
  "grouping": "by_severity|by_asset|by_category|by_time" or null
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at analyzing cybersecurity data queries. Return only valid JSON."
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
            return result
            
        except Exception as e:
            print(f"Error analyzing query: {str(e)}")
            return {
                "intent": "general statistics",
                "query_type": "count",
                "entities": {},
                "time_range": {"specified": False, "period": "all time"},
                "metrics": ["vulnerability_count"],
                "needs_visualization": False,
                "chart_type": None
            }
    
    def _fetch_data_for_query(self, query_analysis, organization_id=None):
        """
        Fetch actual data from database based on query analysis
        """
        
        query_type = query_analysis.get('query_type', 'count')
        entities = query_analysis.get('entities', {})
        time_range = query_analysis.get('time_range', {})
        grouping = query_analysis.get('grouping')
        
        # Build base queryset
        vuln_queryset = Vulnerability.objects.all()
        asset_queryset = Asset.objects.all()
        
        # Apply organization filter
        if organization_id:
            vuln_queryset = vuln_queryset.filter(asset__organization_id=organization_id)
            asset_queryset = asset_queryset.filter(organization_id=organization_id)
        
        # Apply entity filters
        if entities.get('assets'):
            asset_names = entities['assets']
            vuln_queryset = vuln_queryset.filter(asset__name__in=asset_names)
            asset_queryset = asset_queryset.filter(name__in=asset_names)
        
        if entities.get('severities'):
            vuln_queryset = vuln_queryset.filter(severity__in=entities['severities'])
        
        if entities.get('categories'):
            vuln_queryset = vuln_queryset.filter(category__in=entities['categories'])
        
        # Apply time range filter
        if time_range.get('specified') and time_range.get('start_date'):
            vuln_queryset = vuln_queryset.filter(
                created_at__gte=time_range['start_date']
            )
            if time_range.get('end_date'):
                vuln_queryset = vuln_queryset.filter(
                    created_at__lte=time_range['end_date']
                )
        elif time_range.get('period'):
            period = time_range['period']
            if 'month' in period or 'year' in period:
                days = self._parse_period_to_days(period)
                cutoff_date = datetime.now() - timedelta(days=days)
                vuln_queryset = vuln_queryset.filter(created_at__gte=cutoff_date)
        
        # Fetch data based on query type
        result = {}
        
        if query_type == 'count':
            result = self._fetch_count_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'comparison':
            result = self._fetch_comparison_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'trend':
            result = self._fetch_trend_data(vuln_queryset, time_range)
        
        elif query_type == 'ranking':
            result = self._fetch_ranking_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'distribution':
            result = self._fetch_distribution_data(vuln_queryset, grouping)
        
        elif query_type == 'detail':
            result = self._fetch_detail_data(vuln_queryset, asset_queryset, entities)
        
        return result
    
    def _fetch_count_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch count data"""
        
        if grouping == 'by_severity':
            data = vuln_queryset.values('severity').annotate(
                count=Count('id')
            ).order_by('-count')
            
            return {
                'type': 'grouped_count',
                'data': list(data),
                'total': vuln_queryset.count()
            }
        
        elif grouping == 'by_asset':
            data = vuln_queryset.values(
                'asset__name', 'asset__id'
            ).annotate(
                count=Count('id')
            ).order_by('-count')
            
            # Convert UUID to string
            data_list = []
            for item in data:
                data_list.append({
                    'asset__name': item['asset__name'],
                    'asset__id': str(item['asset__id']),
                    'count': item['count']
                })
            
            return {
                'type': 'grouped_count',
                'data': data_list,
                'total': vuln_queryset.count()
            }
        
        elif grouping == 'by_category':
            data = vuln_queryset.values('category').annotate(
                count=Count('id')
            ).order_by('-count')
            
            return {
                'type': 'grouped_count',
                'data': list(data),
                'total': vuln_queryset.count()
            }
        
        else:
            return {
                'type': 'simple_count',
                'vulnerability_count': vuln_queryset.count(),
                'asset_count': asset_queryset.count()
            }
    
    def _fetch_comparison_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch comparison data across multiple dimensions"""
        
        # Compare severity distribution
        severity_data = list(vuln_queryset.values('severity').annotate(
            count=Count('id')
        ))
        
        # Compare by asset
        asset_data = vuln_queryset.values(
            'asset__name', 'asset__id'
        ).annotate(
            count=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low'))
        ).order_by('-count')[:10]
        
        # Convert UUIDs to strings
        asset_data_list = []
        for item in asset_data:
            asset_data_list.append({
                'asset__name': item['asset__name'],
                'asset__id': str(item['asset__id']),
                'count': item['count'],
                'critical': item['critical'],
                'high': item['high'],
                'medium': item['medium'],
                'low': item['low']
            })
        
        return {
            'type': 'comparison',
            'severity_distribution': severity_data,
            'top_assets': asset_data_list
        }
    
    def _fetch_trend_data(self, vuln_queryset, time_range):
        """Fetch trend data over time"""
        
        # Determine time grouping
        period = time_range.get('period', 'all time')
        
        if 'month' in period or 'year' in period:
            # Group by month
            from django.db.models.functions import TruncMonth
            
            trend_data = vuln_queryset.annotate(
                month=TruncMonth('created_at')
            ).values('month').annotate(
                count=Count('id'),
                critical=Count('id', filter=Q(severity='critical')),
                high=Count('id', filter=Q(severity='high')),
                medium=Count('id', filter=Q(severity='medium'))
            ).order_by('month')
            
            return {
                'type': 'trend',
                'grouping': 'monthly',
                'data': [
                    {
                        'date': item['month'].strftime('%Y-%m') if item['month'] else None,
                        'total': item['count'],
                        'critical': item['critical'],
                        'high': item['high'],
                        'medium': item['medium']
                    }
                    for item in trend_data
                ]
            }
        
        return {
            'type': 'trend',
            'data': []
        }
    
    def _fetch_ranking_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch ranking data"""
        
        # Get top vulnerable assets
        asset_rankings = vuln_queryset.values(
            'asset__name', 'asset__id'
        ).annotate(
            total_count=Count('id'),
            critical_count=Count('id', filter=Q(severity='critical')),
            high_count=Count('id', filter=Q(severity='high'))
        ).order_by('-critical_count', '-high_count', '-total_count')[:10]
        
        # Get risk scores if available
        asset_risks = AssetRiskAssessment.objects.filter(
            asset__in=asset_queryset
        ).select_related('asset').order_by('-risk_score')[:10]
        
        return {
            'type': 'ranking',
            'top_vulnerable_assets': [
                {
                    'asset_name': item['asset__name'],
                    'asset_id': str(item['asset__id']),
                    'total_vulnerabilities': item['total_count'],
                    'critical': item['critical_count'],
                    'high': item['high_count']
                }
                for item in asset_rankings
            ],
            'top_risk_scores': [
                {
                    'asset_name': risk.asset.name,
                    'asset_id': str(risk.asset.id),
                    'risk_score': risk.risk_score,
                    'risk_level': risk.risk_level
                }
                for risk in asset_risks
            ]
        }
    
    def _fetch_distribution_data(self, vuln_queryset, grouping):
        """Fetch distribution data"""
        
        severity_dist = vuln_queryset.values('severity').annotate(
            count=Count('id')
        )
        
        category_dist = vuln_queryset.values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        owasp_dist = vuln_queryset.exclude(
            owasp=''
        ).values('owasp').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return {
            'type': 'distribution',
            'severity': list(severity_dist),
            'categories': list(category_dist),
            'owasp': list(owasp_dist)
        }
    
    def _fetch_detail_data(self, vuln_queryset, asset_queryset, entities):
        """Fetch detailed data for specific entities"""
        
        result = {}
        
        if entities.get('assets'):
            asset_name = entities['assets'][0]
            asset = asset_queryset.filter(name__icontains=asset_name).first()
            
            if asset:
                vulns = vuln_queryset.filter(asset=asset)
                
                result['asset_details'] = {
                    'name': asset.name,
                    'id': str(asset.id),
                    'type': asset.asset_type,
                    'total_vulnerabilities': vulns.count(),
                    'severity_breakdown': {
                        'critical': vulns.filter(severity='critical').count(),
                        'high': vulns.filter(severity='high').count(),
                        'medium': vulns.filter(severity='medium').count(),
                        'low': vulns.filter(severity='low').count()
                    },
                    'categories': list(
                        vulns.values('category').annotate(
                            count=Count('id')
                        ).order_by('-count')[:5]
                    )
                }
        
        return {
            'type': 'detail',
            **result
        }
    
    def _generate_answer(self, user_query, query_analysis, data_result, stats):
        """
        Generate natural language answer with visualization data
        """
        
        # Use custom JSON encoder for serialization
        def json_safe_dumps(obj):
            return json.dumps(obj, indent=2, cls=UUIDEncoder)
        
        prompt = f"""Generate a comprehensive answer to the user's question based on the analyzed data.

USER QUESTION: "{user_query}"

QUERY ANALYSIS:
{json_safe_dumps(query_analysis)}

DATA RETRIEVED:
{json_safe_dumps(data_result)}

SYSTEM STATISTICS:
{json_safe_dumps(stats)}

Provide a response with:
1. A clear, natural language answer to the question
2. Key insights and findings
3. If visualization is needed, provide chart configuration

Return JSON:
{{
  "answer": "Natural language answer",
  "insights": ["Key insight 1", "Key insight 2", "Key insight 3"],
  "summary_stats": {{"stat_name": value}},
  "visualization": {{
    "needed": true/false,
    "type": "bar|line|pie|table|multi-line",
    "title": "Chart title",
    "data": {{
      "labels": ["label1", "label2"],
      "datasets": [
        {{
          "label": "Dataset name",
          "data": [value1, value2],
          "backgroundColor": ["color1", "color2"]
        }}
      ]
    }},
    "options": {{
      "description": "What this chart shows"
    }}
  }} or null,
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity analyst providing insights. Return only valid JSON with clear, actionable answers."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.5,
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add raw data for advanced users
            result['raw_data'] = data_result
            result['query_metadata'] = {
                'intent': query_analysis.get('intent'),
                'query_type': query_analysis.get('query_type'),
                'entities_found': query_analysis.get('entities')
            }
            
            return result
            
        except Exception as e:
            print(f"Error generating answer: {str(e)}")
            return {
                "answer": f"I found some data but had trouble formatting the answer. Here's what I found: {len(data_result.get('data', []))} items.",
                "insights": [],
                "visualization": None,
                "raw_data": data_result,
                "summary_stats": {},
                "recommendations": []
            }
    
    def _get_system_statistics(self):
        """Get basic system statistics"""
        
        return {
            'total_organizations': Organization.objects.count(),
            'total_assets': Asset.objects.count(),
            'total_vulnerabilities': Vulnerability.objects.count(),
            'critical_vulnerabilities': Vulnerability.objects.filter(
                severity='critical'
            ).count(),
            'high_risk_assets': AssetRiskAssessment.objects.filter(
                risk_score__gte=70
            ).count()
        }
    
    def _get_comprehensive_statistics(self, organization_id=None):
        """Get comprehensive system statistics"""
        
        vuln_qs = Vulnerability.objects.all()
        asset_qs = Asset.objects.all()
        
        if organization_id:
            vuln_qs = vuln_qs.filter(asset__organization_id=organization_id)
            asset_qs = asset_qs.filter(organization_id=organization_id)
        
        stats = {
            'organizations': Organization.objects.count(),
            'assets': {
                'total': asset_qs.count(),
                'applications': asset_qs.filter(asset_type='application').count(),
                'servers': asset_qs.filter(asset_type='server').count()
            },
            'vulnerabilities': {
                'total': vuln_qs.count(),
                'critical': vuln_qs.filter(severity='critical').count(),
                'high': vuln_qs.filter(severity='high').count(),
                'medium': vuln_qs.filter(severity='medium').count(),
                'low': vuln_qs.filter(severity='low').count()
            },
            'remediations': {
                'total': AIRemediation.objects.count(),
                'helpful': AIRemediation.objects.filter(is_helpful=True).count()
            },
            'risk_assessments': {
                'vulnerabilities_assessed': VulnerabilityRiskAssessment.objects.count(),
                'assets_assessed': AssetRiskAssessment.objects.count(),
                'high_risk_assets': AssetRiskAssessment.objects.filter(
                    risk_score__gte=70
                ).count()
            }
        }
        
        # Get top categories
        top_categories = vuln_qs.values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        stats['top_vulnerability_categories'] = [
            {'category': item['category'], 'count': item['count']}
            for item in top_categories
        ]
        
        return stats
    
    def _parse_period_to_days(self, period):
        """Convert period string to days"""
        
        if '3 month' in period:
            return 90
        elif '6 month' in period:
            return 180
        elif '1 year' in period or 'year' in period:
            return 365
        elif '3 year' in period:
            return 1095
        else:
            return 365  # default to 1 year