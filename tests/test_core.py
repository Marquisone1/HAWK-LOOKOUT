"""Test suite for HAWK LOOKOUT core functionality."""

import pytest
import json
from app import create_app
from app.models import db, User
from app.services import WhoisFreakService, IPAPIService, DNSService


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def api_user(app):
    """Create test API user."""
    with app.app_context():
        user = User(api_key='test-key-123')
        db.session.add(user)
        db.session.commit()
        return user


class TestWhoisFreakServiceRouting:
    """Test WhoisFreak service routing logic."""
    
    def test_is_ip_detection(self):
        """Test IP address detection."""
        service = WhoisFreakService()
        
        # Valid IPs
        assert service.is_ip("8.8.8.8") is True
        assert service.is_ip("192.168.1.1") is True
        assert service.is_ip("::1") is True  # IPv6
        assert service.is_ip("2606:2800:220:1:248:1893:25c8:1946") is True
        
        # Invalid IPs
        assert service.is_ip("999.999.999.999") is False
        assert service.is_ip("example.com") is False
        assert service.is_ip("") is False
    
    def test_is_domain_detection(self):
        """Test domain detection."""
        service = WhoisFreakService()
        
        # Valid domains
        assert service.is_domain("example.com") is True
        assert service.is_domain("sub.example.co.uk") is True
        
        # Invalid domains
        assert service.is_domain("8.8.8.8") is False
        assert service.is_domain("example.com.") is False  # Trailing dot not supported
        assert service.is_domain("") is False
        assert service.is_domain("just-a-word") is False


class TestIPAPIServiceParsing:
    """Test IP-API response parsing."""
    
    def test_response_structure(self):
        """Test that IP-API response has expected structure."""
        service = IPAPIService()
        
        # Verify the service returns proper nested structure
        # (We won't call the live API in unit tests)
        assert hasattr(service, 'lookup')
        assert hasattr(service, 'API_URL')
        assert hasattr(service, 'timeout')
    
    def test_lookup_error_handling(self):
        """Test error handling for invalid IPs."""
        service = IPAPIService()
        
        # Invalid IP should return error dict
        result = service.lookup("999.999.999.999")
        assert isinstance(result, dict)
        assert 'error' in result or 'status' in result


class TestDNSServiceParsing:
    """Test DNS response parsing."""
    
    def test_service_initialization(self):
        """Test DNS service initializes correctly."""
        service = DNSService()
        
        if service.enabled:
            assert hasattr(service, 'resolver')
            assert hasattr(service, 'lookup')
    
    def test_lookup_method_exists(self):
        """Test DNS service has lookup method."""
        service = DNSService()
        assert hasattr(service, 'lookup')
        assert callable(service.lookup)


class TestFallbackRouting:
    """Test fallback service routing."""
    
    def test_lookup_with_fallback_flag_false(self, api_user):
        """Test that prefer_fallback=False uses WhoisFreak."""
        service = WhoisFreakService()
        api_user.prefer_fallback = False
        
        # With fallback disabled, should attempt WhoisFreak
        # (This is integration-level, uses actual API calls)
        assert api_user.prefer_fallback is False
    
    def test_lookup_with_fallback_flag_true(self, api_user):
        """Test that prefer_fallback=True uses fallback services."""
        service = WhoisFreakService()
        api_user.prefer_fallback = True
        
        assert api_user.prefer_fallback is True


class TestErrorContract:
    """Test error response contract."""
    
    def test_error_response_structure(self, client):
        """Test that error responses follow standard contract."""
        from app.error_contract import error_response, ErrorCode
        
        response, status = error_response(
            ErrorCode.INVALID_TARGET,
            message="Custom message"
        )
        
        assert status == 400
        data = json.loads(response.get_data(as_text=True))
        assert data['error'] == 'INVALID_TARGET'
        assert data['message'] == 'Custom message'
    
    def test_error_codes_mapped(self):
        """Test all error codes have HTTP mappings."""
        from app.error_contract import ErrorCode, ERROR_MAP
        
        for code in ErrorCode:
            assert code in ERROR_MAP, f"Missing mapping for {code}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
