"""Infrastructure graph for entity relationships."""

from app.models import LookupHistory
from typing import Dict, List, Set


class InfrastructureGraph:
    """Track relationships: Domain ↔ IP ↔ ASN ↔ NS ↔ Registrar."""
    
    def build_from_lookup(lookup_id: int) -> Dict:
        """Build graph from a single lookup."""
        lookup = LookupHistory.query.get(lookup_id)
        if not lookup:
            return {}
        
        data = lookup.get_result_dict()
        graph = {
            'nodes': {},
            'edges': [],
            'pivot_targets': set()
        }
        
        # Extract entities
        if lookup.ip_address:  # Domain lookup
            domain = data.get('data', {}).get('domain_name', lookup.ip_address)
            graph['nodes'][('domain', domain)] = {'type': 'domain', 'value': domain}
            
            # Nameservers
            ns = data.get('data', {}).get('name_servers', [])
            for nameserver in ns:
                graph['nodes'][('ns', nameserver)] = {'type': 'ns', 'value': nameserver}
                graph['edges'].append((('domain', domain), ('ns', nameserver), 'uses_ns'))
                graph['pivot_targets'].add(('ns', nameserver))
            
            # MX records
            mx = data.get('data', {}).get('mx_records', [])
            for mx_record in mx:
                exchange = mx_record.get('exchange', '')
                graph['nodes'][('mx', exchange)] = {'type': 'mx', 'value': exchange}
                graph['edges'].append((('domain', domain), ('mx', exchange), 'uses_mx'))
                graph['pivot_targets'].add(('mx', exchange))
            
            # Registrar
            registrar = data.get('data', {}).get('domain_registrar', {})
            if registrar.get('registrar_name'):
                graph['nodes'][('registrar', registrar['registrar_name'])] = {
                    'type': 'registrar',
                    'value': registrar['registrar_name']
                }
                graph['edges'].append((('domain', domain), ('registrar', registrar['registrar_name']), 'registered_by'))
        
        else:  # IP lookup
            ip = lookup.ip_address
            graph['nodes'][('ip', ip)] = {'type': 'ip', 'value': ip}
            
            # Organization/ASN
            org = data.get('data', {}).get('organization', {})
            if org.get('name'):
                graph['nodes'][('org', org['name'])] = {'type': 'org', 'value': org['name']}
                graph['edges'].append((('ip', ip), ('org', org['name']), 'belongs_to'))
                graph['pivot_targets'].add(('org', org['name']))
            
            if org.get('country'):
                graph['nodes'][('country', org['country'])] = {'type': 'country', 'value': org['country']}
                graph['edges'].append((('ip', ip), ('country', org['country']), 'located_in'))
        
        return graph
    
    @staticmethod
    def find_related_lookups(entity_type: str, entity_value: str) -> List[LookupHistory]:
        """Find all lookups mentioning this entity."""
        results = []
        
        # Search database for related entities
        lookups = LookupHistory.query.all()
        for lookup in lookups:
            data = lookup.get_result_dict()
            
            # Simple text search (production would use JSON indexing)
            result_json = str(data)
            if entity_value.lower() in result_json.lower():
                results.append(lookup)
        
        return results
    
    @staticmethod
    def cluster_by_infrastructure(lookups: List[LookupHistory]) -> Dict[str, List]:
        """Group lookups by shared infrastructure."""
        clusters = {}
        
        for lookup in lookups:
            data = lookup.get_result_dict()
            
            # Group by ASN/Org
            org = data.get('data', {}).get('organization', {}).get('name', 'Unknown')
            if org not in clusters:
                clusters[org] = []
            clusters[org].append(lookup)
        
        return clusters
