import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import structlog
from app.config.settings import settings

logger = structlog.get_logger(__name__)


class EmailPort:
    """Service for sending emails for password recovery and notifications"""

    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.sender_email = settings.SENDER_EMAIL
        self.sender_password = settings.SENDER_PASSWORD
        self.use_tls = settings.SMTP_USE_TLS

    async def send_password_recovery_email(self, recipient_email: str, recovery_token: str, recovery_link: str) -> bool:
        """Send password recovery email with token and recovery link
        
        Args:
            recipient_email: Email address of the user
            recovery_token: The token to reset password
            recovery_link: The full URL for password recovery (e.g., http://frontend.com/reset?token=xyz)
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            logger.info("Preparing to send password recovery email", recipient_email=recipient_email)

            subject = "🔐 Recuperación de Contraseña - LDAP-DAII-G3"

            # HTML email body - Modern professional design
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f5f7fa;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                        overflow: hidden;
                    }}
                    .header {{
                        background: linear-gradient(135deg, #04BF8A 0%, #026B73 100%);
                        padding: 30px;
                        color: white;
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 28px;
                        font-weight: 600;
                    }}
                    .content {{
                        padding: 40px;
                    }}
                    .greeting {{
                        font-size: 16px;
                        color: #333;
                        margin-bottom: 20px;
                    }}
                    .message {{
                        font-size: 14px;
                        color: #555;
                        line-height: 1.8;
                        margin-bottom: 30px;
                    }}
                    .cta-button {{
                        display: inline-block;
                        background: linear-gradient(135deg, #04bf8a 0%);
                        color: white;
                        padding: 14px 40px;
                        text-decoration: none;
                        border-radius: 6px;
                        font-weight: 600;
                        font-size: 16px;
                        text-align: center;
                        margin: 20px 0;
                        transition: transform 0.2s;
                    }}
                    .cta-button:hover {{
                        transform: translateY(-2px);
                    }}
                    .token-section {{
                        background-color: #f8f9fa;
                        border-left: 4px solid #04BF8A;
                        padding: 20px;
                        margin: 30px 0;
                        border-radius: 4px;
                    }}
                    .token-label {{
                        font-size: 12px;
                        color: #666;
                        text-transform: uppercase;
                        font-weight: 600;
                        margin-bottom: 10px;
                    }}
                    .token-code {{
                        font-family: 'Courier New', monospace;
                        font-size: 13px;
                        color: #333;
                        word-break: break-all;
                        background-color: #ffffff;
                        padding: 12px;
                        border-radius: 4px;
                        border: 1px solid #ddd;
                    }}
                    .expiration-notice {{
                        background-color: #ccefe5;
                        border: 1px solid #04BF8A;
                        border-radius: 4px;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 13px;
                        color: #856404;
                    }}
                    .footer {{
                        background-color: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        border-top: 1px solid #e9ecef;
                        font-size: 12px;
                        color: #666;
                    }}
                    .footer a {{
                        color: #667eea;
                        text-decoration: none;
                    }}
                    .divider {{
                        height: 1px;
                        background-color: #e9ecef;
                        margin: 20px 0;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Recuperación de Contraseña</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Acceso Seguro a tu Cuenta</p>
                    </div>
                    
                    <div class="content">
                        <p class="greeting">Hola,</p>
                        
                        <p class="message">
                            Recibimos una solicitud para restablecer la contraseña de tu cuenta <strong>LDAP-DAII-G3</strong>. 
                            Si no realizaste esta solicitud, puedes ignorar este correo de forma segura.
                        </p>
                        
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{recovery_link}" class="cta-button">Restablecer Contraseña</a>
                        </p>
                        
                        <p class="message" style="text-align: center; color: #666; font-size: 13px;">
                            O copia y pega este token en el formulario de restablecimiento de contraseña:
                        </p>
                        
                        <div class="token-section">
                            <div class="token-label">Token de Recuperación</div>
                            <div class="token-code">{recovery_token}</div>
                        </div>
                        
                        <div class="expiration-notice">
                            ⏱️ Este enlace de recuperación y token expiran en <strong>24 horas</strong> por razones de seguridad.
                        </div>
                        
                        <div class="divider"></div>
                        
                        <p style="font-size: 13px; color: #666; margin: 20px 0 0 0;">
                            <strong>Consejos de Seguridad:</strong>
                        </p>
                        <ul style="font-size: 13px; color: #666; margin: 10px 0; padding-left: 20px;">
                            <li>Nunca compartas tu token de recuperación con nadie</li>
                            <li>Solo utiliza enlaces de correos oficiales</li>
                            <li>Si no solicitaste esto, contacta a tu administrador de inmediato</li>
                        </ul>
                    </div>
                    
                    <div class="footer">
                        <p style="margin: 0;">
                            © 2024 Sistema LDAP-DAII-G3. Todos los derechos reservados.
                        </p>
                        <p style="margin: 8px 0 0 0;">
                            ¿Necesitas ayuda? <a href="#">Contactar Soporte</a>
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Plain text body as fallback
            text_body = f"""
SOLICITUD DE RECUPERACIÓN DE CONTRASEÑA
========================================

Hola,

Recibimos una solicitud para restablecer la contraseña de tu cuenta LDAP-DAII-G3.
Si no realizaste esta solicitud, puedes ignorar este correo de forma segura.

RESTABLECER CONTRASEÑA
======================
Visita este enlace: {recovery_link}

TOKEN DE RECUPERACIÓN
=====================
{recovery_token}

AVISO DE SEGURIDAD IMPORTANTE
=============================
- Este enlace de recuperación y token expiran en 24 horas
- Nunca compartas tu token de recuperación con nadie
- Solo utiliza enlaces de correos oficiales
- Si no solicitaste esto, contacta a tu administrador de inmediato

© 2025 Sistema LDAP-DAII-G3. Todos los derechos reservados.
¿Necesitas ayuda? Contactar Soporte
            """

            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = recipient_email

            # Attach both plain text and HTML versions
            part1 = MIMEText(text_body, "plain")
            part2 = MIMEText(html_body, "html")
            message.attach(part1)
            message.attach(part2)

            # Send email
            if self.use_tls:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.sender_email, self.sender_password)
                    server.send_message(message)
                    logger.info("Password recovery email sent successfully", recipient_email=recipient_email)
            else:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                    server.login(self.sender_email, self.sender_password)
                    server.send_message(message)
                    logger.info("Password recovery email sent successfully (SSL)", recipient_email=recipient_email)

            return True

        except smtplib.SMTPException as e:
            logger.error("SMTP error while sending password recovery email", recipient_email=recipient_email, error=str(e))
            return False
        except Exception as e:
            logger.error("Error sending password recovery email", recipient_email=recipient_email, error=str(e))
            return False

    async def send_password_changed_notification(self, recipient_email: str) -> bool:
        """Send confirmation email when password is changed
        
        Args:
            recipient_email: Email address of the user
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            logger.info("Preparing to send password changed notification", recipient_email=recipient_email)

            subject = "✅ Contraseña Cambiada Exitosamente - LDAP-DAII-G3"

            # HTML email body - Modern professional design
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f5f7fa;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                        overflow: hidden;
                    }}
                    .header {{
                        background: linear-gradient(135deg, #04BF8A 0%, #026B73 100%);
                        padding: 30px;
                        color: white;
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 28px;
                        font-weight: 600;
                    }}
                    .content {{
                        padding: 40px;
                    }}
                    .greeting {{
                        font-size: 16px;
                        color: #333;
                        margin-bottom: 20px;
                    }}
                    .message {{
                        font-size: 14px;
                        color: #555;
                        line-height: 1.8;
                        margin-bottom: 30px;
                    }}
                    .success-box {{
                        background-color: #ccefe5;
                        border: 2px solid #04BF8A;
                        border-radius: 6px;
                        padding: 20px;
                        margin: 20px 0;
                        text-align: center;
                    }}
                    .success-box .checkmark {{
                        font-size: 40px;
                        margin-bottom: 10px;
                    }}
                    .success-box p {{
                        margin: 0;
                        color: #026B73;
                        font-weight: 600;
                    }}
                    .alert-box {{
                        background-color: #ccefe5;
                        border-left: 4px solid #025940;
                        padding: 15px;
                        margin: 20px 0;
                        border-radius: 4px;
                        font-size: 13px;
                        color: #024059;
                    }}
                    .alert-box strong {{
                        color: #026B73;
                    }}
                    .footer {{
                        background-color: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        border-top: 1px solid #e9ecef;
                        font-size: 12px;
                        color: #666;
                    }}
                    .footer a {{
                        color: #04BF8A;
                        text-decoration: none;
                    }}
                    .divider {{
                        height: 1px;
                        background-color: #e9ecef;
                        margin: 20px 0;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Contraseña Cambiada</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Tu cuenta está segura</p>
                    </div>
                    
                    <div class="content">
                        <p class="greeting">Hola,</p>
                        
                        <div class="success-box">
                            <div class="checkmark">✓</div>
                            <p>Tu contraseña para LDAP-DAII-G3 ha sido cambiada exitosamente</p>
                        </div>
                        
                        <p class="message">
                            La contraseña de tu cuenta ha sido actualizada exitosamente. Ahora puedes iniciar sesión con tus nuevas credenciales.
                        </p>
                        
                        <div class="alert-box">
                            <strong>⚠️ Alerta de Seguridad:</strong><br>
                            Si no realizaste este cambio o no reconoces esta actividad, 
                            <strong>contacta a tu administrador de inmediato</strong>.
                        </div>
                        
                        <div class="divider"></div>
                        
                        <p style="font-size: 13px; color: #666; margin: 20px 0 0 0;">
                            <strong>Recordatorios de Seguridad:</strong>
                        </p>
                        <ul style="font-size: 13px; color: #666; margin: 10px 0; padding-left: 20px;">
                            <li>Nunca compartas tu contraseña con nadie</li>
                            <li>Usa una contraseña fuerte y única para tu cuenta</li>
                            <li>Mantén tu contraseña confidencial en todo momento</li>
                            <li>Cierra sesión cuando uses dispositivos compartidos</li>
                        </ul>
                    </div>
                    
                    <div class="footer">
                        <p style="margin: 0;">
                            © 2024 Sistema LDAP-DAII-G3. Todos los derechos reservados.
                        </p>
                        <p style="margin: 8px 0 0 0;">
                            ¿Preguntas? <a href="#">Contactar Soporte</a>
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Plain text body as fallback
            text_body = f"""
CONTRASEÑA CAMBIADA EXITOSAMENTE
=================================

Hola,

Tu contraseña para LDAP-DAII-G3 ha sido cambiada exitosamente.
Ahora puedes iniciar sesión con tus nuevas credenciales.

ALERTA DE SEGURIDAD
===================
Si no realizaste este cambio o no reconoces esta actividad,
contacta a tu administrador de inmediato.

RECORDATORIOS DE SEGURIDAD
==========================
- Nunca compartas tu contraseña con nadie
- Usa una contraseña fuerte y única para tu cuenta
- Mantén tu contraseña confidencial en todo momento
- Cierra sesión cuando uses dispositivos compartidos

© 2025 Sistema LDAP-DAII-G3. Todos los derechos reservados.
¿Preguntas? Contactar Soporte
            """

            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = recipient_email

            part1 = MIMEText(text_body, "plain")
            part2 = MIMEText(html_body, "html")
            message.attach(part1)
            message.attach(part2)

            if self.use_tls:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.sender_email, self.sender_password)
                    server.send_message(message)
            else:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                    server.login(self.sender_email, self.sender_password)
                    server.send_message(message)

            logger.info("Password changed notification sent successfully", recipient_email=recipient_email)
            return True

        except Exception as e:
            logger.error("Error sending password changed notification", recipient_email=recipient_email, error=str(e))
            return False
