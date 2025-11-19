import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.ports.outbound.email_port import EmailPort


@pytest.fixture
def email_port():
    """Create EmailPort instance with mocked settings"""
    with patch('app.ports.outbound.email_port.settings') as mock_settings:
        mock_settings.SMTP_SERVER = "smtp.test.com"
        mock_settings.SMTP_PORT = 587
        mock_settings.SENDER_EMAIL = "noreply@test.com"
        mock_settings.SENDER_PASSWORD = "password123"
        mock_settings.SMTP_USE_TLS = True
        return EmailPort()


class TestEmailPortPasswordRecovery:
    """Test password recovery email sending"""

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_success_with_tls(self, email_port):
        """Test successful password recovery email sending with TLS"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            # Setup mock SMTP
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_recovery_email(
                recipient_email="user@example.com",
                recovery_token="test-token-123",
                recovery_link="http://example.com/reset?token=test-token-123"
            )

            assert result is True
            mock_smtp.assert_called_once_with("smtp.test.com", 587)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("noreply@test.com", "password123")
            mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_success_with_ssl(self, email_port):
        """Test successful password recovery email sending with SSL"""
        email_port.use_tls = False
        
        with patch('app.ports.outbound.email_port.smtplib.SMTP_SSL') as mock_smtp_ssl:
            mock_server = MagicMock()
            mock_smtp_ssl.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_recovery_email(
                recipient_email="user@example.com",
                recovery_token="test-token-456",
                recovery_link="http://example.com/reset?token=test-token-456"
            )

            assert result is True
            mock_smtp_ssl.assert_called_once_with("smtp.test.com", 587)
            mock_server.login.assert_called_once_with("noreply@test.com", "password123")
            mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_smtp_exception(self, email_port):
        """Test password recovery email with SMTP exception"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.__enter__.side_effect = smtplib.SMTPException("SMTP error")

            result = await email_port.send_password_recovery_email(
                recipient_email="user@example.com",
                recovery_token="test-token-789",
                recovery_link="http://example.com/reset?token=test-token-789"
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_general_exception(self, email_port):
        """Test password recovery email with general exception"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.__enter__.side_effect = Exception("Connection failed")

            result = await email_port.send_password_recovery_email(
                recipient_email="user@example.com",
                recovery_token="test-token-abc",
                recovery_link="http://example.com/reset?token=test-token-abc"
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_with_special_characters(self, email_port):
        """Test password recovery email with special characters in token and link"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_recovery_email(
                recipient_email="user+tag@example.com",
                recovery_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                recovery_link="http://example.com/reset?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&lang=es"
            )

            assert result is True
            mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_password_recovery_email_contains_correct_content(self, email_port):
        """Test that recovery email contains recovery link and token"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            recovery_link = "http://example.com/reset?token=abc123"
            recovery_token = "abc123"

            await email_port.send_password_recovery_email(
                recipient_email="user@example.com",
                recovery_token=recovery_token,
                recovery_link=recovery_link
            )

            # Get the message that was sent
            send_message_call = mock_server.send_message.call_args
            message = send_message_call[0][0]

            # Verify message headers
            assert message["To"] == "user@example.com"
            assert message["From"] == "noreply@test.com"
            assert "Recuperación" in message["Subject"] or "Recuperacion" in message["Subject"]

            # Verify message contains the token and link by checking message parts
            # MIME messages encode content, so we need to check the payloads
            has_token = False
            has_link = False
            
            for part in message.walk():
                payload = part.get_payload(decode=True)
                if payload:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if recovery_token in payload_str:
                        has_token = True
                    if recovery_link in payload_str:
                        has_link = True
            
            assert has_token, f"Token '{recovery_token}' not found in message parts"
            assert has_link, f"Link '{recovery_link}' not found in message parts"


class TestEmailPortPasswordChanged:
    """Test password changed notification email sending"""

    @pytest.mark.asyncio
    async def test_send_password_changed_notification_success_with_tls(self, email_port):
        """Test successful password changed notification with TLS"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_changed_notification(
                recipient_email="user@example.com"
            )

            assert result is True
            mock_smtp.assert_called_once_with("smtp.test.com", 587)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once()
            mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_password_changed_notification_success_with_ssl(self, email_port):
        """Test successful password changed notification with SSL"""
        email_port.use_tls = False
        
        with patch('app.ports.outbound.email_port.smtplib.SMTP_SSL') as mock_smtp_ssl:
            mock_server = MagicMock()
            mock_smtp_ssl.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_changed_notification(
                recipient_email="user@example.com"
            )

            assert result is True
            mock_smtp_ssl.assert_called_once()
            mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_password_changed_notification_exception(self, email_port):
        """Test password changed notification with exception"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.__enter__.side_effect = Exception("Email service down")

            result = await email_port.send_password_changed_notification(
                recipient_email="user@example.com"
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_send_password_changed_notification_contains_correct_content(self, email_port):
        """Test that notification contains success message"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            await email_port.send_password_changed_notification(
                recipient_email="user@example.com"
            )

            send_message_call = mock_server.send_message.call_args
            message = send_message_call[0][0]

            assert message["To"] == "user@example.com"
            assert message["From"] == "noreply@test.com"
            assert "Cambiad" in message["Subject"] or "Cambiada" in message["Subject"]

            # Check message parts for success message
            found_success = False
            for part in message.walk():
                payload = part.get_payload(decode=True)
                if payload:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if "exitosamente" in payload_str.lower() or "success" in payload_str.lower():
                        found_success = True
                        break
            
            assert found_success, "Success message not found in email parts"

    @pytest.mark.asyncio
    async def test_send_password_changed_notification_with_special_email(self, email_port):
        """Test password changed notification with special email format"""
        with patch('app.ports.outbound.email_port.smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = await email_port.send_password_changed_notification(
                recipient_email="user.name+tag@example.co.uk"
            )

            assert result is True
            mock_server.send_message.assert_called_once()

            send_message_call = mock_server.send_message.call_args
            message = send_message_call[0][0]
            assert message["To"] == "user.name+tag@example.co.uk"


class TestEmailPortInitialization:
    """Test EmailPort initialization and configuration"""

    def test_email_port_initialization(self, email_port):
        """Test EmailPort initializes with correct settings"""
        assert email_port.smtp_server == "smtp.test.com"
        assert email_port.smtp_port == 587
        assert email_port.sender_email == "noreply@test.com"
        assert email_port.sender_password == "password123"
        assert email_port.use_tls is True

    def test_email_port_ssl_configuration(self):
        """Test EmailPort with SSL configuration"""
        with patch('app.ports.outbound.email_port.settings') as mock_settings:
            mock_settings.SMTP_SERVER = "smtp.gmail.com"
            mock_settings.SMTP_PORT = 465
            mock_settings.SENDER_EMAIL = "app@gmail.com"
            mock_settings.SENDER_PASSWORD = "app_password"
            mock_settings.SMTP_USE_TLS = False
            
            port = EmailPort()
            
            assert port.smtp_port == 465
            assert port.use_tls is False
