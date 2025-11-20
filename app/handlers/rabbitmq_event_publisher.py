"""
RabbitMQ Event Publishing Handler

This module provides utilities for publishing events to RabbitMQ across the application.
Follow this pattern when integrating RabbitMQ into your handlers and services.

Example:
    from app.handlers.rabbitmq_event_publisher import publish_user_event

    # In your user handler
    async def create_user_handler(user_data):
        user = await user_service.create(user_data)
        await publish_user_event("user.created", user.id, user.email)
        return user
"""

import structlog
from typing import Any, Dict, Optional
from app.infra.rabbitmq_service_factory import get_rabbitmq_port_instance

logger = structlog.get_logger()


async def publish_ldap_event(
    event_type: str,
    event_data: Dict[str, Any],
    source: str = "LDAP_SERVICE"
) -> bool:
    """
    Publish LDAP-related events to RabbitMQ.

    Args:
        event_type: Type of event (e.g., 'user.created', 'organization.deleted')
        event_data: Dictionary containing event details
        source: Event source identifier

    Returns:
        bool: True if published successfully

    Example:
        await publish_ldap_event(
            "user.created",
            {"username": "john.doe", "organization": "IT"},
            source="USER_SERVICE"
        )
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_message(
            message_body={
                "event_type": event_type,
                "source": source,
                **event_data
            }
        )
    except Exception as e:
        logger.error(
            "Failed to publish LDAP event",
            event_type=event_type,
            error=str(e)
        )
        return False


async def publish_authentication_event(
    status: str,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    error_reason: Optional[str] = None,
    ip_address: Optional[str] = None
) -> bool:
    """
    Publish authentication-related events.

    Args:
        status: 'SUCCESS' or 'FAILURE'
        username: Username attempting authentication
        user_id: User ID (if successful)
        error_reason: Reason for failure (if failed)
        ip_address: IP address of the requester

    Returns:
        bool: True if published successfully
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_log_message(
            log_level="INFO" if status == "SUCCESS" else "WARNING",
            message=f"Authentication {status.lower()}",
            source="AUTH_SERVICE",
            status=status,
            username=username,
            user_id=user_id,
            error_reason=error_reason,
            ip_address=ip_address
        )
    except Exception as e:
        logger.error(
            "Failed to publish authentication event",
            status=status,
            error=str(e)
        )
        return False


async def publish_user_operation_event(
    operation: str,
    username: str,
    status: str,
    performed_by: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Publish user operation audit events (create, update, delete).

    Args:
        operation: Operation type (CREATE, UPDATE, DELETE)
        username: Username of the affected user
        status: Operation status (SUCCESS, FAILURE)
        performed_by: User performing the operation
        details: Additional operation details

    Returns:
        bool: True if published successfully
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_audit_log(
            action=f"USER_{operation}",
            user=performed_by or "SYSTEM",
            resource=f"users:{username}",
            status=status,
            username=username,
            **(details or {})
        )
    except Exception as e:
        logger.error(
            "Failed to publish user operation event",
            operation=operation,
            error=str(e)
        )
        return False


async def publish_organization_operation_event(
    operation: str,
    organization_name: str,
    status: str,
    performed_by: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Publish organization operation audit events.

    Args:
        operation: Operation type (CREATE, UPDATE, DELETE)
        organization_name: Name of the organization
        status: Operation status (SUCCESS, FAILURE)
        performed_by: User performing the operation
        details: Additional operation details

    Returns:
        bool: True if published successfully
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_audit_log(
            action=f"ORGANIZATION_{operation}",
            user=performed_by or "SYSTEM",
            resource=f"organizations:{organization_name}",
            status=status,
            organization_name=organization_name,
            **(details or {})
        )
    except Exception as e:
        logger.error(
            "Failed to publish organization operation event",
            operation=operation,
            error=str(e)
        )
        return False


async def publish_role_operation_event(
    operation: str,
    role_name: str,
    status: str,
    performed_by: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Publish role management audit events.

    Args:
        operation: Operation type (CREATE, UPDATE, DELETE, ASSIGN)
        role_name: Name of the role
        status: Operation status (SUCCESS, FAILURE)
        performed_by: User performing the operation
        details: Additional operation details

    Returns:
        bool: True if published successfully
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_audit_log(
            action=f"ROLE_{operation}",
            user=performed_by or "SYSTEM",
            resource=f"roles:{role_name}",
            status=status,
            role_name=role_name,
            **(details or {})
        )
    except Exception as e:
        logger.error(
            "Failed to publish role operation event",
            operation=operation,
            error=str(e)
        )
        return False


async def publish_error_event(
    error_type: str,
    error_message: str,
    context: Optional[Dict[str, Any]] = None,
    stacktrace: Optional[str] = None
) -> bool:
    """
    Publish application error events for monitoring and debugging.

    Args:
        error_type: Type of error (e.g., 'ValidationError', 'LDAPConnectionError')
        error_message: Error message
        context: Additional context about the error
        stacktrace: Full stacktrace if available

    Returns:
        bool: True if published successfully
    """
    try:
        rabbitmq_port = await get_rabbitmq_port_instance()
        return await rabbitmq_port.publish_log_message(
            log_level="ERROR",
            message=error_message,
            source="ERROR_HANDLER",
            error_type=error_type,
            stacktrace=stacktrace,
            **(context or {})
        )
    except Exception as e:
        logger.error(
            "Failed to publish error event",
            error_type=error_type,
            error=str(e)
        )
        return False
