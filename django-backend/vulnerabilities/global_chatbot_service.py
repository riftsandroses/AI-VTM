"""
Global Chatbot Service - AI-powered analytics and insights
Provides natural language querying with auto-suggestions and visualizations
UPDATED: More flexible queries, broader analytics, 4 graph types only
"""
from django.conf import settings
from openai import OpenAI
import json
from datetime import datetime, timedelta, date
from django.db.models import Count, Q, Avg, Sum, Max, Min
from uuid import UUID
from decimal import Decimal
from collections import defaultdict
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
        UPDATED: More diverse and comprehensive suggestions
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

TYPES OF QUESTIONS USERS CAN ASK:

1. COUNT & STATISTICS:
   - "How many assets have critical vulnerabilities?"
   - "What percentage of vulnerabilities are high severity?"
   - "Count vulnerabilities by severity level"

2. COMPARISONS:
   - "Compare vulnerability counts across organizations"
   - "Which asset has more vulnerabilities: X vs Y?"
   - "Compare risk scores between applications and servers"

3. TRENDS & TIME SERIES:
   - "Show vulnerability trends over the past year"
   - "How have critical vulnerabilities changed monthly?"
   - "Trend of remediation generation over time"

4. RANKINGS & TOP/BOTTOM:
   - "Top 10 most vulnerable assets"
   - "Which organizations have the highest risk?"
   - "Most common vulnerability categories"

5. DISTRIBUTIONS:
   - "Distribution of vulnerabilities by severity"
   - "Breakdown of assets by type"
   - "OWASP Top 10 distribution in our system"

6. CORRELATIONS & PATTERNS:
   - "Correlation between asset type and vulnerability count"
   - "Which technology stacks have most vulnerabilities?"
   - "Pattern of vulnerabilities across different severities"

7. DETAILED ANALYSIS:
   - "Analyze vulnerabilities in [asset name]"
   - "Deep dive into critical vulnerabilities"
   - "Show me SQL Injection vulnerabilities with their risk scores"

8. AGGREGATIONS:
   - "Average risk score by organization"
   - "Total vulnerabilities per asset grouped by severity"
   - "Sum of critical issues by month"

9. PREDICTIVE/INSIGHTS:
   - "Which assets need immediate attention?"
   - "What are the emerging vulnerability trends?"
   - "Risk hotspots in our infrastructure"

10. CROSS-DIMENSIONAL:
    - "Vulnerabilities by asset type and severity"
    - "Risk assessment distribution across organizations and assets"
    - "Remediation effectiveness by vulnerability category"

Return ONLY a JSON array of 5 suggested complete questions that:
1. Complete or extend the user's partial query
2. Are diverse and cover different analytical angles
3. Can generate interesting visualizations
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
                        "content": "You are a data analytics assistant suggesting insightful questions about cybersecurity vulnerability data. Return only valid JSON."
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
        UPDATED: More flexible, always tries to generate appropriate visualizations
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
        
        # Generate natural language answer with visualization
        answer = self._generate_answer(user_query, query_analysis, data_result, stats)
        
        # Final cleanup of any remaining UUIDs
        answer = convert_uuids_to_strings(answer)
        
        return answer
    
    def _analyze_query(self, user_query, stats):
        """
        Use AI to analyze user query and determine intent, entities, and visualization needs
        UPDATED: More flexible query types and always suggests visualization
        """
        
        prompt = f"""Analyze this user query about cybersecurity vulnerabilities and extract detailed information.

USER QUERY: "{user_query}"

AVAILABLE DATA SUMMARY:
{json.dumps(stats, indent=2)}

Analyze the query and determine:

1. **Intent**: What the user wants to know (be specific)

2. **Query Type**: Choose the most appropriate type:
   - count: Simple counting queries
   - comparison: Comparing metrics across entities
   - trend: Time-based analysis
   - ranking: Top N or Bottom N queries
   - distribution: Breakdown/percentage analysis
   - correlation: Relationship between variables
   - aggregation: Sum, average, min, max calculations
   - detailed_analysis: Deep dive into specific entities
   - pattern_discovery: Finding patterns or anomalies
   - multi_dimensional: Cross-tabulation or pivot analysis

3. **Entities**: Extract specific names, types, or filters mentioned

4. **Time Range**: Any time period specified

5. **Metrics**: What measurements are needed

6. **Aggregation Level**: Individual items, grouped, or summarized

7. **Visualization**: ALWAYS recommend a visualization unless explicitly asked not to show graphs
   - Supported types: "bar", "line", "pie", "heatmap"
   - Choose the most appropriate type for the data
   - Default to bar charts for comparisons and counts
   - Use line charts for trends over time
   - Use pie charts for percentage distributions (max 10 slices)
   - Use heatmaps for multi-dimensional correlations

8. **Grouping/Dimensions**: How to group or break down the data

Return JSON:
{{
  "intent": "detailed description of what user wants",
  "query_type": "one of the types above",
  "entities": {{
    "assets": ["asset names mentioned"],
    "organizations": ["org names mentioned"],
    "severities": ["critical", "high", etc],
    "categories": ["SQL Injection", etc],
    "other_filters": ["any other filters"]
  }},
  "time_range": {{
    "specified": true/false,
    "period": "3 months|6 months|1 year|all time",
    "start_date": "YYYY-MM-DD or null",
    "end_date": "YYYY-MM-DD or null"
  }},
  "metrics": ["vulnerability_count", "risk_score", "percentage", "average", etc],
  "aggregation_level": "individual|grouped|summarized",
  "visualization": {{
    "recommended": true,
    "type": "bar|line|pie|heatmap",
    "reason": "why this visualization type"
  }},
  "grouping": {{
    "primary": "by_severity|by_asset|by_category|by_time|by_organization|by_risk_level|by_type",
    "secondary": "optional secondary grouping",
    "limit": 10
  }},
  "sort_by": "metric to sort by",
  "sort_order": "desc|asc"
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at analyzing data analytics queries. Always recommend appropriate visualizations. Return only valid JSON."
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
            
            # Ensure visualization is always recommended unless explicitly declined
            if not result.get('visualization', {}).get('recommended', True):
                result['visualization'] = {
                    'recommended': True,
                    'type': 'bar',
                    'reason': 'Default bar chart for data visualization'
                }
            
            return result
            
        except Exception as e:
            print(f"Error analyzing query: {str(e)}")
            return {
                "intent": "general statistics",
                "query_type": "count",
                "entities": {},
                "time_range": {"specified": False, "period": "all time"},
                "metrics": ["vulnerability_count"],
                "aggregation_level": "summarized",
                "visualization": {
                    "recommended": True,
                    "type": "bar",
                    "reason": "Default visualization"
                },
                "grouping": {"primary": "by_severity", "limit": 10},
                "sort_by": "count",
                "sort_order": "desc"
            }
    
    def _fetch_data_for_query(self, query_analysis, organization_id=None):
        """
        Fetch actual data from database based on query analysis
        UPDATED: More flexible data fetching supporting various analytical queries
        """
        
        query_type = query_analysis.get('query_type', 'count')
        entities = query_analysis.get('entities', {})
        time_range = query_analysis.get('time_range', {})
        grouping = query_analysis.get('grouping', {})
        metrics = query_analysis.get('metrics', [])
        
        # Build base querysets
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
            result = self._fetch_trend_data(vuln_queryset, time_range, grouping)
        
        elif query_type == 'ranking':
            result = self._fetch_ranking_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'distribution':
            result = self._fetch_distribution_data(vuln_queryset, grouping)
        
        elif query_type == 'correlation':
            result = self._fetch_correlation_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'aggregation':
            result = self._fetch_aggregation_data(vuln_queryset, asset_queryset, grouping, metrics)
        
        elif query_type == 'multi_dimensional':
            result = self._fetch_multi_dimensional_data(vuln_queryset, asset_queryset, grouping)
        
        elif query_type == 'pattern_discovery':
            result = self._fetch_pattern_data(vuln_queryset, asset_queryset, grouping)
        
        else:  # detailed_analysis
            result = self._fetch_detail_data(vuln_queryset, asset_queryset, entities)
        
        return result
    
    def _fetch_count_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch count data with flexible grouping"""
        
        primary_group = grouping.get('primary', 'by_severity')
        limit = grouping.get('limit', 10)
        
        if primary_group == 'by_severity':
            data = vuln_queryset.values('severity').annotate(
                count=Count('id')
            ).order_by('-count')
            
        elif primary_group == 'by_asset':
            data = vuln_queryset.values(
                'asset__name', 'asset__id'
            ).annotate(
                count=Count('id')
            ).order_by('-count')[:limit]
            
            data = [
                {
                    'asset_name': item['asset__name'],
                    'asset_id': str(item['asset__id']),
                    'count': item['count']
                }
                for item in data
            ]
            
        elif primary_group == 'by_category':
            data = vuln_queryset.values('category').annotate(
                count=Count('id')
            ).order_by('-count')[:limit]
            
        elif primary_group == 'by_organization':
            data = vuln_queryset.values(
                'asset__organization__name'
            ).annotate(
                count=Count('id')
            ).order_by('-count')[:limit]
            
        elif primary_group == 'by_risk_level':
            risk_assessments = VulnerabilityRiskAssessment.objects.filter(
                vulnerability__in=vuln_queryset
            ).values('risk_level').annotate(
                count=Count('id')
            ).order_by('-count')
            data = list(risk_assessments)
            
        elif primary_group == 'by_type':
            data = vuln_queryset.values(
                'asset__asset_type'
            ).annotate(
                count=Count('id')
            ).order_by('-count')
            
        else:
            data = [{'total': vuln_queryset.count()}]
        
        return {
            'type': 'count',
            'grouping': primary_group,
            'data': list(data),
            'total': vuln_queryset.count()
        }
    
    def _fetch_comparison_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch comparison data across multiple dimensions"""
        
        # Multi-dimensional comparison
        severity_by_asset = vuln_queryset.values(
            'asset__name', 'severity'
        ).annotate(
            count=Count('id')
        ).order_by('asset__name', 'severity')
        
        # Pivot the data
        comparison_matrix = {}
        for item in severity_by_asset:
            asset_name = item['asset__name']
            if asset_name not in comparison_matrix:
                comparison_matrix[asset_name] = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'informational': 0
                }
            comparison_matrix[asset_name][item['severity']] = item['count']
        
        return {
            'type': 'comparison',
            'comparison_matrix': comparison_matrix,
            'summary': {
                'total_assets': len(comparison_matrix),
                'severities': ['critical', 'high', 'medium', 'low', 'informational']
            }
        }
    
    def _fetch_trend_data(self, vuln_queryset, time_range, grouping):
        """Fetch trend data over time"""
        
        from django.db.models.functions import TruncMonth, TruncWeek, TruncDay
        
        # Determine granularity
        period = time_range.get('period', '6 months')
        
        if 'day' in period or int(period.split()[0]) <= 7:
            trunc_func = TruncDay
            date_format = '%Y-%m-%d'
        elif 'week' in period or int(period.split()[0]) <= 30:
            trunc_func = TruncWeek
            date_format = '%Y-W%W'
        else:
            trunc_func = TruncMonth
            date_format = '%Y-%m'
        
        trend_data = vuln_queryset.annotate(
            period=trunc_func('created_at')
        ).values('period').annotate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low'))
        ).order_by('period')
        
        return {
            'type': 'trend',
            'granularity': trunc_func.__name__,
            'data': [
                {
                    'date': item['period'].strftime(date_format) if item['period'] else None,
                    'total': item['total'],
                    'critical': item['critical'],
                    'high': item['high'],
                    'medium': item['medium'],
                    'low': item['low']
                }
                for item in trend_data
            ]
        }
    
    def _fetch_ranking_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch ranking data"""
        
        limit = grouping.get('limit', 10)
        
        # Assets ranking by vulnerability count
        asset_rankings = vuln_queryset.values(
            'asset__name', 'asset__id'
        ).annotate(
            total_count=Count('id'),
            critical_count=Count('id', filter=Q(severity='critical')),
            high_count=Count('id', filter=Q(severity='high')),
            risk_score=Avg('risk_assessment__risk_score')
        ).order_by('-critical_count', '-high_count', '-total_count')[:limit]
        
        return {
            'type': 'ranking',
            'top_items': [
                {
                    'asset_name': item['asset__name'],
                    'asset_id': str(item['asset__id']),
                    'total_vulnerabilities': item['total_count'],
                    'critical': item['critical_count'],
                    'high': item['high_count'],
                    'avg_risk_score': float(item['risk_score']) if item['risk_score'] else 0
                }
                for item in asset_rankings
            ]
        }
    
    def _fetch_distribution_data(self, vuln_queryset, grouping):
        """Fetch distribution data"""
        
        severity_dist = vuln_queryset.values('severity').annotate(
            count=Count('id')
        )
        
        total = vuln_queryset.count()
        
        return {
            'type': 'distribution',
            'total': total,
            'severity_distribution': [
                {
                    'severity': item['severity'],
                    'count': item['count'],
                    'percentage': round((item['count'] / total * 100), 2) if total > 0 else 0
                }
                for item in severity_dist
            ]
        }
    
    def _fetch_correlation_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch correlation data between different dimensions"""
        
        # Asset type vs Severity correlation
        correlation_data = vuln_queryset.values(
            'asset__asset_type', 'severity'
        ).annotate(
            count=Count('id')
        ).order_by('asset__asset_type', 'severity')
        
        # Build correlation matrix
        matrix = {}
        for item in correlation_data:
            asset_type = item['asset__asset_type']
            severity = item['severity']
            
            if asset_type not in matrix:
                matrix[asset_type] = {}
            
            matrix[asset_type][severity] = item['count']
        
        return {
            'type': 'correlation',
            'matrix': matrix
        }
    
    def _fetch_aggregation_data(self, vuln_queryset, asset_queryset, grouping, metrics):
        """Fetch aggregated metrics"""
        
        aggregations = {}
        
        if 'average_risk_score' in metrics or 'risk_score' in metrics:
            avg_risk = VulnerabilityRiskAssessment.objects.filter(
                vulnerability__in=vuln_queryset
            ).aggregate(
                avg=Avg('risk_score'),
                min=Min('risk_score'),
                max=Max('risk_score')
            )
            aggregations['risk_scores'] = avg_risk
        
        if 'vulnerability_count' in metrics:
            aggregations['total_vulnerabilities'] = vuln_queryset.count()
            
        # Group by asset and aggregate
        by_asset = vuln_queryset.values('asset__name').annotate(
            count=Count('id'),
            avg_risk=Avg('risk_assessment__risk_score')
        ).order_by('-count')[:10]
        
        aggregations['by_asset'] = list(by_asset)
        
        return {
            'type': 'aggregation',
            'aggregations': aggregations
        }
    
    def _fetch_multi_dimensional_data(self, vuln_queryset, asset_queryset, grouping):
        """Fetch multi-dimensional cross-tabulated data"""
        
        # Three-way breakdown: Organization -> Asset Type -> Severity
        multi_dim = vuln_queryset.values(
            'asset__organization__name',
            'asset__asset_type',
            'severity'
        ).annotate(
            count=Count('id')
        ).order_by('asset__organization__name', 'asset__asset_type', 'severity')
        
        # Organize into hierarchical structure
        hierarchy = {}
        for item in multi_dim:
            org = item['asset__organization__name']
            asset_type = item['asset__asset_type']
            severity = item['severity']
            count = item['count']
            
            if org not in hierarchy:
                hierarchy[org] = {}
            if asset_type not in hierarchy[org]:
                hierarchy[org][asset_type] = {}
            
            hierarchy[org][asset_type][severity] = count
        
        return {
            'type': 'multi_dimensional',
            'hierarchy': hierarchy
        }
    
    def _fetch_pattern_data(self, vuln_queryset, asset_queryset, grouping):
        """Discover patterns and anomalies"""
        
        # Find assets with unusual vulnerability patterns
        asset_stats = vuln_queryset.values('asset__name', 'asset__id').annotate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high'))
        ).order_by('-total')
        
        avg_vulns = vuln_queryset.count() / asset_queryset.count() if asset_queryset.count() > 0 else 0
        
        anomalies = [
            {
                'asset_name': item['asset__name'],
                'asset_id': str(item['asset__id']),
                'total': item['total'],
                'critical': item['critical'],
                'high': item['high'],
                'deviation': item['total'] - avg_vulns,
                'is_anomaly': item['total'] > (avg_vulns * 2)
            }
            for item in asset_stats
            if item['total'] > (avg_vulns * 1.5)  # 50% above average
        ]
        
        return {
            'type': 'pattern_discovery',
            'average_vulnerabilities_per_asset': round(avg_vulns, 2),
            'anomalies': anomalies
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
                    'top_categories': list(
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
        UPDATED: Always generates appropriate visualizations
        """
        
        def json_safe_dumps(obj):
            return json.dumps(obj, indent=2, cls=UUIDEncoder)
        
        visualization_info = query_analysis.get('visualization', {})
        recommended_viz_type = visualization_info.get('type', 'bar')
        
        prompt = f"""Generate a comprehensive answer to the user's question with appropriate data visualization.

USER QUESTION: "{user_query}"

QUERY ANALYSIS:
{json_safe_dumps(query_analysis)}

DATA RETRIEVED:
{json_safe_dumps(data_result)}

SYSTEM STATISTICS:
{json_safe_dumps(stats)}

VISUALIZATION REQUIREMENTS:
- Type Recommended: {recommended_viz_type}
- Supported Types: bar, line, pie, heatmap
- ALWAYS create a visualization unless data is insufficient

CHART TYPE GUIDELINES:
1. **Bar Chart**: Best for comparisons, counts, rankings
   - Use vertical bars for categorical comparisons
   - Can have multiple series for grouped data
   
2. **Line Chart**: Best for trends over time
   - Show progression and changes
   - Can have multiple lines for comparison
   
3. **Pie Chart**: Best for percentage distributions
   - Limit to 10 slices maximum
   - Show parts of a whole
   
4. **Heatmap**: Best for correlation matrices, multi-dimensional data
   - Show intensity across two dimensions
   - Use color gradients

Provide a response with:
1. A clear, natural language answer
2. Key insights and findings
3. Summary statistics
4. Appropriate visualization configuration
5. Actionable recommendations

Return JSON:
{{
  "answer": "Natural language answer explaining the data and insights",
  "insights": [
    "Key insight 1 with specific numbers",
    "Key insight 2 showing patterns",
    "Key insight 3 highlighting important findings"
  ],
  "summary_stats": {{
    "key_metric_1": value,
    "key_metric_2": value,
    "key_metric_3": value
  }},
  "visualization": {{
    "type": "bar|line|pie|heatmap",
    "title": "Descriptive chart title",
    "description": "What this visualization shows",
    "config": {{
      // For BAR charts:
      "labels": ["Label 1", "Label 2", ...],
      "datasets": [
        {{
          "label": "Dataset name",
          "data": [value1, value2, ...],
          "backgroundColor": ["#FF6384", "#36A2EB", "#FFCE56", ...],
          "borderColor": ["#FF6384", "#36A2EB", "#FFCE56", ...],
          "borderWidth": 1
        }}
      ],
      
      // For LINE charts:
      "labels": ["Period 1", "Period 2", ...],
      "datasets": [
        {{
          "label": "Metric name",
          "data": [value1, value2, ...],
          "borderColor": "#FF6384",
          "backgroundColor": "rgba(255, 99, 132, 0.2)",
          "tension": 0.4,
          "fill": true
        }}
      ],
      
      // For PIE charts:
      "labels": ["Category 1", "Category 2", ...],
      "datasets": [
        {{
          "data": [value1, value2, ...],
          "backgroundColor": [
            "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
            "#FF9F40", "#FF6384", "#C9CBCF", "#4BC0C0", "#FF6384"
          ]
        }}
      ],
      
      // For HEATMAP:
      "x_labels": ["X1", "X2", ...],
      "y_labels": ["Y1", "Y2", ...],
      "data": [
        [value11, value12, ...],
        [value21, value22, ...],
        ...
      ],
      "colorScale": {{
        "min": 0,
        "max": 100,
        "colors": ["#00ff00", "#ffff00", "#ff0000"]
      }}
    }},
    "options": {{
      "responsive": true,
      "maintainAspectRatio": false,
      "plugins": {{
        "legend": {{"display": true, "position": "top"}},
        "tooltip": {{"enabled": true}}
      }}
    }}
  }},
  "recommendations": [
    "Actionable recommendation 1",
    "Actionable recommendation 2"
  ]
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a data analytics expert providing insights with clear visualizations. Always create appropriate charts. Return only valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.5,
                max_tokens=3000,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Ensure visualization exists
            if not result.get('visualization') or not result['visualization'].get('type'):
                # Generate a default visualization based on data
                result['visualization'] = self._generate_fallback_visualization(
                    data_result,
                    recommended_viz_type
                )
            
            # Add raw data for advanced users
            result['raw_data'] = data_result
            result['query_metadata'] = {
                'intent': query_analysis.get('intent'),
                'query_type': query_analysis.get('query_type'),
                'entities_found': query_analysis.get('entities'),
                'visualization_type': result.get('visualization', {}).get('type')
            }
            
            return result
            
        except Exception as e:
            print(f"Error generating answer: {str(e)}")
            
            # Return a basic response with fallback visualization
            return {
                "answer": f"I found data related to your query. Here's what I discovered based on the available information.",
                "insights": [
                    f"Total data points analyzed: {len(data_result.get('data', []))}",
                    "Please see the visualization for detailed breakdown"
                ],
                "visualization": self._generate_fallback_visualization(data_result, recommended_viz_type),
                "raw_data": data_result,
                "summary_stats": {},
                "recommendations": ["Review the visualization for detailed insights"]
            }
    
    def _generate_fallback_visualization(self, data_result, viz_type='bar'):
        """Generate a fallback visualization when AI doesn't create one"""
        
        data_type = data_result.get('type', 'count')
        data = data_result.get('data', [])
        
        if not data:
            return None
        
        # Generate bar chart as default
        if viz_type == 'bar' or data_type in ['count', 'ranking', 'comparison']:
            labels = []
            values = []
            
            for item in data[:10]:  # Limit to 10 items
                if 'severity' in item:
                    labels.append(item['severity'])
                    values.append(item.get('count', 0))
                elif 'asset_name' in item:
                    labels.append(item['asset_name'])
                    values.append(item.get('count', item.get('total', 0)))
                elif 'category' in item:
                    labels.append(item['category'])
                    values.append(item.get('count', 0))
            
            return {
                'type': 'bar',
                'title': 'Data Analysis Results',
                'description': 'Visualization of query results',
                'config': {
                    'labels': labels,
                    'datasets': [{
                        'label': 'Count',
                        'data': values,
                        'backgroundColor': [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                            '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
                        ][:len(values)]
                    }]
                },
                'options': {
                    'responsive': True,
                    'plugins': {
                        'legend': {'display': True}
                    }
                }
            }
        
        # Generate line chart for trends
        elif viz_type == 'line' or data_type == 'trend':
            dates = [item.get('date', item.get('period', f'Period {i+1}')) for i, item in enumerate(data)]
            totals = [item.get('total', item.get('count', 0)) for item in data]
            
            return {
                'type': 'line',
                'title': 'Trend Analysis',
                'description': 'Trend over time',
                'config': {
                    'labels': dates,
                    'datasets': [{
                        'label': 'Total',
                        'data': totals,
                        'borderColor': '#36A2EB',
                        'backgroundColor': 'rgba(54, 162, 235, 0.2)',
                        'tension': 0.4,
                        'fill': True
                    }]
                },
                'options': {
                    'responsive': True,
                    'plugins': {
                        'legend': {'display': True}
                    }
                }
            }
        
        # Generate pie chart for distributions
        elif viz_type == 'pie' or data_type == 'distribution':
            labels = []
            values = []
            
            for item in data[:10]:
                if 'severity' in item:
                    labels.append(item['severity'])
                    values.append(item.get('count', item.get('percentage', 0)))
                elif 'category' in item:
                    labels.append(item['category'])
                    values.append(item.get('count', 0))
            
            return {
                'type': 'pie',
                'title': 'Distribution Analysis',
                'description': 'Percentage distribution',
                'config': {
                    'labels': labels,
                    'datasets': [{
                        'data': values,
                        'backgroundColor': [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                            '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
                        ][:len(values)]
                    }]
                },
                'options': {
                    'responsive': True,
                    'plugins': {
                        'legend': {'display': True, 'position': 'right'}
                    }
                }
            }
        
        return None
    
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