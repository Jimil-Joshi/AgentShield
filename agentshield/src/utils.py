"""
AgentShield Utilities
LLM provider setup, env loading, ID generation, logging.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

logger = logging.getLogger("agentshield")


def load_env() -> None:
    """Load environment variables from .env file."""
    # Try multiple locations
    for candidate in [".env", "../.env", "../../.env"]:
        if os.path.exists(candidate):
            load_dotenv(candidate)
            return
    load_dotenv()


def setup_logging(level: int = logging.INFO) -> None:
    """Configure structured logging for AgentShield."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_timestamp() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


def generate_id(prefix: str = "") -> str:
    """Generate a short unique ID with optional prefix."""
    short = uuid.uuid4().hex[:12]
    return f"{prefix}_{short}" if prefix else short


def get_llm(provider: Optional[str] = None, temperature: float = 0.0):
    """
    Get an LLM instance. Tries AWS Bedrock (Claude 3.5 Sonnet) first,
    falls back to Azure OpenAI.

    Args:
        provider: Force a specific provider ('bedrock' or 'azure').
        temperature: LLM temperature (default 0.0 for deterministic output).

    Returns:
        A LangChain chat model instance.
    """
    load_env()

    if provider != "azure":
        try:
            from langchain_aws import ChatBedrock

            model_id = os.getenv(
                "BEDROCK_MODEL_ID",
                "anthropic.claude-3-5-sonnet-20241022-v2:0",
            )
            llm = ChatBedrock(
                model_id=model_id,
                region_name=os.getenv("AWS_REGION_NAME", "us-west-2"),
                model_kwargs={
                    "temperature": temperature,
                    "max_tokens": 4096,
                },
            )
            logger.info("Using AWS Bedrock: %s", model_id)
            return llm
        except Exception as exc:
            logger.warning("Bedrock unavailable (%s), trying Azure fallback…", exc)

    # Fallback: Azure OpenAI
    try:
        from langchain_openai import AzureChatOpenAI

        llm = AzureChatOpenAI(
            azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4.1-mini"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT", ""),
            api_key=os.getenv("AZURE_OPENAI_API_KEY", ""),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
            temperature=temperature,
            max_tokens=4096,
        )
        logger.info("Using Azure OpenAI: %s", os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"))
        return llm
    except Exception as exc:
        logger.error("Azure OpenAI also unavailable: %s", exc)
        raise RuntimeError(
            "No LLM provider available. Set AWS or Azure credentials in .env"
        ) from exc


# ── Security helpers ────────────────────────────────────────────

SECURITY_PATTERNS = [
    "verify(", "authenticate(", "validate(", "sanitize(",
    "check_auth(", "require_auth(", "is_authenticated(",
    "check_permission(", "authorize(", "csrf_protect(",
    "rate_limit(", "encrypt(", "decrypt(", "hash_password(",
]

CREDENTIAL_PATTERNS = [
    ".env", "credentials", "secrets", "api_key", "apikey",
    "password", "token", "private_key", "secret_key",
    "aws_access_key", "aws_secret", ".pem", ".key",
]

AUTH_FILE_PATTERNS = [
    "auth", "login", "authenticate", "session", "permission",
    "access_control", "rbac", "oauth", "jwt", "token",
]

PII_PATTERNS = [
    "pii", "personal", "user_data", "ssn", "credit_card",
    "email", "phone", "address", "name", "dob", "date_of_birth",
]


def contains_security_logic(content: str) -> bool:
    """Check if content contains security-related function calls."""
    lower = content.lower()
    return any(p.lower() in lower for p in SECURITY_PATTERNS)


def is_credential_file(file_path: str) -> bool:
    """Check if a file path suggests credential storage."""
    lower = file_path.lower()
    return any(p in lower for p in CREDENTIAL_PATTERNS)


def is_auth_file(file_path: str) -> bool:
    """Check if a file path is authentication-related."""
    lower = file_path.lower().replace("\\", "/")
    parts = lower.split("/")
    filename = parts[-1] if parts else lower
    return any(p in filename for p in AUTH_FILE_PATTERNS)


def is_test_file(file_path: str) -> bool:
    """Check if a file is a test file."""
    lower = file_path.lower().replace("\\", "/")
    parts = lower.split("/")
    filename = parts[-1] if parts else lower
    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or "/tests/" in lower
        or "/test/" in lower
        or "spec/" in lower
    )
