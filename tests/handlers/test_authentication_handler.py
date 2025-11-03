import pytest
from unittest.mock import MagicMock, patch
from fastapi import Request, HTTPException, status
from app.handlers.authentication.authentication_handler import (
    _extract_token_from_auth_header,
    _decode_roles_from_jwt,
    _require_roles
)


@pytest.fixture
def mock_request():
    request = MagicMock(spec=Request)
    return request


class TestExtractTokenFromAuthHeader:
    def test_extract_token_bearer_format(self, mock_request):
        """Test extracting token from Bearer format"""
        mock_request.headers.get.side_effect = lambda x: "Bearer my_token_123"
        
        token = _extract_token_from_auth_header(mock_request)
        assert token == "my_token_123"

    def test_extract_token_bearer_lowercase(self, mock_request):
        """Test extracting token from bearer (lowercase) format"""
        mock_request.headers.get.side_effect = lambda x: "bearer my_token_456"
        
        token = _extract_token_from_auth_header(mock_request)
        assert token == "my_token_456"

    def test_extract_token_single_part(self, mock_request):
        """Test extracting token when only token is provided (no Bearer)"""
        mock_request.headers.get.side_effect = lambda x: "my_token_789"
        
        token = _extract_token_from_auth_header(mock_request)
        assert token == "my_token_789"

    def test_extract_token_missing_header(self, mock_request):
        """Test missing Authorization header raises 401"""
        mock_request.headers.get.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            _extract_token_from_auth_header(mock_request)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Missing Authorization header" in exc_info.value.detail

    def test_extract_token_invalid_format(self, mock_request):
        """Test invalid Authorization header format raises 401"""
        mock_request.headers.get.side_effect = lambda x: "Bearer token1 token2 token3"
        
        with pytest.raises(HTTPException) as exc_info:
            _extract_token_from_auth_header(mock_request)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid Authorization header" in exc_info.value.detail

    def test_extract_token_case_insensitive_header_key(self, mock_request):
        """Test that header extraction tries both 'authorization' and 'Authorization'"""
        # First call returns None (lowercase), second returns Bearer token
        mock_request.headers.get.side_effect = [None, "Bearer my_token"]
        
        token = _extract_token_from_auth_header(mock_request)
        assert token == "my_token"


class TestDecodeRolesFromJwt:
    @patch('app.handlers.authentication.authentication_handler.TokenValidationRequest')
    def test_decode_roles_success(self, mock_token_class):
        """Test successful JWT decoding with roles"""
        mock_token = MagicMock()
        mock_token.decode_jwt.return_value = {
            "roles": ["admin", "user"],
            "sub": "alice"
        }
        mock_token_class.return_value = mock_token
        
        roles = _decode_roles_from_jwt("valid_token")
        assert roles == ["admin", "user"]

    @patch('app.handlers.authentication.authentication_handler.TokenValidationRequest')
    def test_decode_roles_empty_list(self, mock_token_class):
        """Test JWT with no roles"""
        mock_token = MagicMock()
        mock_token.decode_jwt.return_value = {"sub": "bob"}
        mock_token_class.return_value = mock_token
        
        roles = _decode_roles_from_jwt("token_no_roles")
        assert roles == []

    @patch('app.handlers.authentication.authentication_handler.TokenValidationRequest')
    def test_decode_roles_invalid_token(self, mock_token_class):
        """Test invalid token raises 401"""
        mock_token = MagicMock()
        mock_token.decode_jwt.side_effect = Exception("Invalid token")
        mock_token_class.return_value = mock_token
        
        with pytest.raises(HTTPException) as exc_info:
            _decode_roles_from_jwt("invalid_token")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token" in exc_info.value.detail

    @patch('app.handlers.authentication.authentication_handler.TokenValidationRequest')
    def test_decode_roles_none_value(self, mock_token_class):
        """Test JWT with roles=None"""
        mock_token = MagicMock()
        mock_token.decode_jwt.return_value = {"roles": None}
        mock_token_class.return_value = mock_token
        
        roles = _decode_roles_from_jwt("token_with_none")
        assert roles == []


class TestRequireRoles:
    @patch('app.handlers.authentication.authentication_handler._extract_token_from_auth_header')
    @patch('app.handlers.authentication.authentication_handler._decode_roles_from_jwt')
    async def test_require_roles_authorized(self, mock_decode, mock_extract, mock_request):
        """Test user with required role is authorized"""
        mock_extract.return_value = "token"
        mock_decode.return_value = ["admin", "user"]
        
        # Should not raise
        await _require_roles(mock_request, ["admin"])

    @patch('app.handlers.authentication.authentication_handler._extract_token_from_auth_header')
    @patch('app.handlers.authentication.authentication_handler._decode_roles_from_jwt')
    async def test_require_roles_insufficient(self, mock_decode, mock_extract, mock_request):
        """Test user without required role is forbidden"""
        mock_extract.return_value = "token"
        mock_decode.return_value = ["user"]
        
        with pytest.raises(HTTPException) as exc_info:
            await _require_roles(mock_request, ["admin"])
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Forbidden" in exc_info.value.detail

    @patch('app.handlers.authentication.authentication_handler._extract_token_from_auth_header')
    @patch('app.handlers.authentication.authentication_handler._decode_roles_from_jwt')
    async def test_require_roles_multiple_allowed(self, mock_decode, mock_extract, mock_request):
        """Test user with one of multiple allowed roles"""
        mock_extract.return_value = "token"
        mock_decode.return_value = ["user"]
        
        # Should not raise - user has one of the allowed roles
        await _require_roles(mock_request, ["admin", "user"])

    @patch('app.handlers.authentication.authentication_handler._extract_token_from_auth_header')
    @patch('app.handlers.authentication.authentication_handler._decode_roles_from_jwt')
    async def test_require_roles_empty_user_roles(self, mock_decode, mock_extract, mock_request):
        """Test user with no roles"""
        mock_extract.return_value = "token"
        mock_decode.return_value = []
        
        with pytest.raises(HTTPException) as exc_info:
            await _require_roles(mock_request, ["admin"])
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @patch('app.handlers.authentication.authentication_handler._extract_token_from_auth_header')
    async def test_require_roles_missing_token(self, mock_extract, mock_request):
        """Test missing token propagates 401"""
        mock_extract.side_effect = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await _require_roles(mock_request, ["admin"])
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
