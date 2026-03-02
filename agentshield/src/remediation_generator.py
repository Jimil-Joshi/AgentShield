"""
AgentShield Remediation Generator (Part 5 sub-component)
Generates specific, actionable fix suggestions with code snippets.
Template-based for common vulns, LLM-enhanced for complex cases.
"""

from __future__ import annotations

import logging
from typing import Optional

from .models import (
    RemediationGuidance,
    SASTFinding,
    TriagePriority,
    VulnType,
)

logger = logging.getLogger("agentshield.remediation")


# ─────────────────────────────────────────────
# Remediation Templates (no LLM needed)
# ─────────────────────────────────────────────

REMEDIATION_TEMPLATES: dict[VulnType, dict] = {
    VulnType.SQL_INJECTION: {
        "description": (
            "Use parameterized queries instead of string formatting/concatenation "
            "to prevent SQL injection. Never interpolate user input directly into SQL."
        ),
        "code_snippet": (
            "# VULNERABLE (DO NOT USE):\n"
            "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "\n"
            "# SECURE (parameterized query):\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "\n"
            "# For SQLAlchemy ORM:\n"
            "from sqlalchemy import text\n"
            "result = session.execute(\n"
            "    text(\"SELECT * FROM users WHERE id = :user_id\"),\n"
            "    {\"user_id\": user_id}\n"
            ")\n"
            "\n"
            "# For Django ORM:\n"
            "User.objects.filter(id=user_id)  # ORM handles parameterization"
        ),
        "effort_estimate": "1-2 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    VulnType.XSS: {
        "description": (
            "Escape all user-supplied data before rendering in HTML. "
            "Use templating engines with auto-escaping enabled."
        ),
        "code_snippet": (
            "import html\n"
            "\n"
            "# VULNERABLE:\n"
            "# return f'<h1>Welcome {username}</h1>'\n"
            "\n"
            "# SECURE (manual escaping):\n"
            "return f'<h1>Welcome {html.escape(username)}</h1>'\n"
            "\n"
            "# SECURE (Jinja2 auto-escaping):\n"
            "# In Flask, use render_template() — it auto-escapes by default\n"
            "from flask import render_template\n"
            "return render_template('dashboard.html', username=username)\n"
            "\n"
            "# For React/JS: Use JSX (auto-escapes) — avoid dangerouslySetInnerHTML"
        ),
        "effort_estimate": "1-2 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    VulnType.HARDCODED_SECRET: {
        "description": (
            "Move all secrets to environment variables or a secrets manager. "
            "Never commit secrets to source code."
        ),
        "code_snippet": (
            "import os\n"
            "\n"
            "# VULNERABLE:\n"
            "# API_KEY = 'sk-abc123-real-key'\n"
            "# DB_PASSWORD = 'production_password'\n"
            "\n"
            "# SECURE (environment variables):\n"
            "API_KEY = os.getenv('API_KEY')\n"
            "DB_PASSWORD = os.getenv('DB_PASSWORD')\n"
            "\n"
            "# SECURE (secrets manager - AWS):\n"
            "import boto3\n"
            "client = boto3.client('secretsmanager')\n"
            "secret = client.get_secret_value(SecretId='my-api-key')\n"
            "\n"
            "# Add to .gitignore:\n"
            "# .env\n"
            "# *.pem\n"
            "# *.key"
        ),
        "effort_estimate": "30 minutes",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    },
    VulnType.PATH_TRAVERSAL: {
        "description": (
            "Validate and sanitize file paths. Use os.path.realpath() to resolve "
            "symbolic links and '..' components, then verify the resolved path "
            "starts with the expected base directory."
        ),
        "code_snippet": (
            "import os\n"
            "\n"
            "ALLOWED_BASE = '/app/uploads'\n"
            "\n"
            "def safe_read_file(user_path: str) -> str:\n"
            "    # Resolve to absolute path\n"
            "    full_path = os.path.realpath(os.path.join(ALLOWED_BASE, user_path))\n"
            "\n"
            "    # Verify it's within allowed directory\n"
            "    if not full_path.startswith(os.path.realpath(ALLOWED_BASE)):\n"
            "        raise PermissionError('Path traversal detected')\n"
            "\n"
            "    with open(full_path) as f:\n"
            "        return f.read()"
        ),
        "effort_estimate": "1-2 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    VulnType.MISSING_AUTH: {
        "description": (
            "Add authentication and authorization checks to all sensitive endpoints. "
            "Use decorator patterns for consistent enforcement."
        ),
        "code_snippet": (
            "from functools import wraps\n"
            "from flask import request, abort, g\n"
            "\n"
            "def require_auth(f):\n"
            "    @wraps(f)\n"
            "    def decorated(*args, **kwargs):\n"
            "        token = request.headers.get('Authorization')\n"
            "        if not token or not verify_token(token):\n"
            "            abort(401)\n"
            "        return f(*args, **kwargs)\n"
            "    return decorated\n"
            "\n"
            "def require_role(role):\n"
            "    def decorator(f):\n"
            "        @wraps(f)\n"
            "        def decorated(*args, **kwargs):\n"
            "            if g.user.role != role:\n"
            "                abort(403)\n"
            "            return f(*args, **kwargs)\n"
            "        return decorated\n"
            "    return decorator\n"
            "\n"
            "@app.route('/admin')\n"
            "@require_auth\n"
            "@require_role('admin')\n"
            "def admin_dashboard():\n"
            "    return render_template('admin.html')"
        ),
        "effort_estimate": "2-4 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
    },
    VulnType.COMMAND_INJECTION: {
        "description": (
            "Never pass user input directly to shell commands. "
            "Use subprocess with shell=False and argument lists."
        ),
        "code_snippet": (
            "import subprocess\n"
            "import shlex\n"
            "\n"
            "# VULNERABLE:\n"
            "# os.system(f'ping {user_input}')\n"
            "\n"
            "# SECURE:\n"
            "subprocess.run(\n"
            "    ['ping', '-c', '1', user_input],  # argument list, not shell=True\n"
            "    capture_output=True, text=True, timeout=10,\n"
            "    check=False  # don't raise on non-zero exit\n"
            ")"
        ),
        "effort_estimate": "1-2 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    VulnType.SSRF: {
        "description": (
            "Validate and restrict URLs before making server-side requests. "
            "Use allowlists for permitted domains/IPs."
        ),
        "code_snippet": (
            "from urllib.parse import urlparse\n"
            "\n"
            "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n"
            "\n"
            "def safe_fetch(url: str):\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.hostname not in ALLOWED_HOSTS:\n"
            "        raise ValueError(f'Host not allowed: {parsed.hostname}')\n"
            "    if parsed.scheme not in ('http', 'https'):\n"
            "        raise ValueError(f'Scheme not allowed: {parsed.scheme}')\n"
            "    # Additional: block private IP ranges\n"
            "    import ipaddress\n"
            "    try:\n"
            "        ip = ipaddress.ip_address(parsed.hostname)\n"
            "        if ip.is_private:\n"
            "            raise ValueError('Private IP not allowed')\n"
            "    except ValueError:\n"
            "        pass  # hostname, not IP — OK if in allowlist\n"
            "    return requests.get(url, timeout=10)"
        ),
        "effort_estimate": "2-3 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
    VulnType.INSECURE_DESERIALIZATION: {
        "description": (
            "Never deserialize untrusted data with pickle or eval. "
            "Use JSON or other safe serialization formats."
        ),
        "code_snippet": (
            "import json\n"
            "\n"
            "# VULNERABLE:\n"
            "# import pickle\n"
            "# data = pickle.loads(user_input)\n"
            "\n"
            "# SECURE:\n"
            "data = json.loads(user_input)  # JSON is safe for deserialization\n"
            "\n"
            "# If you MUST use pickle, use hmac verification:\n"
            "import hmac, hashlib\n"
            "def safe_unpickle(data: bytes, signature: str, key: bytes):\n"
            "    expected = hmac.new(key, data, hashlib.sha256).hexdigest()\n"
            "    if not hmac.compare_digest(signature, expected):\n"
            "        raise ValueError('Tampered data detected')\n"
            "    return pickle.loads(data)  # only after verification"
        ),
        "effort_estimate": "2-4 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    },
    VulnType.BROKEN_ACCESS_CONTROL: {
        "description": (
            "Implement proper authorization checks. Verify the authenticated user "
            "has permission to access the requested resource."
        ),
        "code_snippet": (
            "# VULNERABLE:\n"
            "# @app.route('/user/<user_id>/data')\n"
            "# def get_user_data(user_id):\n"
            "#     return db.get_user(user_id)  # no authz check!\n"
            "\n"
            "# SECURE:\n"
            "@app.route('/user/<user_id>/data')\n"
            "@require_auth\n"
            "def get_user_data(user_id):\n"
            "    if g.current_user.id != user_id and g.current_user.role != 'admin':\n"
            "        abort(403, 'Not authorized to access this user\\'s data')\n"
            "    return db.get_user(user_id)"
        ),
        "effort_estimate": "2-4 hours",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/862.html",
        ],
    },
}


class RemediationGenerator:
    """
    Generates actionable remediation guidance for vulnerabilities.
    Template-based for common vulns, with optional LLM enhancement.
    """

    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self._llm = None

    def generate(
        self,
        finding: SASTFinding,
        priority: TriagePriority,
        code_context: Optional[dict] = None,
    ) -> RemediationGuidance:
        """
        Generate remediation guidance for a SAST finding.

        Args:
            finding: The SAST finding needing remediation.
            priority: The calculated triage priority.
            code_context: Optional code file context for specificity.

        Returns:
            RemediationGuidance with description, code snippet, and references.
        """
        template = REMEDIATION_TEMPLATES.get(finding.vuln_type)

        if template:
            guidance = RemediationGuidance(
                description=template["description"],
                code_snippet=template["code_snippet"],
                effort_estimate=self._adjust_effort(template["effort_estimate"], priority),
                references=template["references"],
            )
        else:
            # Generic guidance for unknown vulnerability types
            guidance = RemediationGuidance(
                description=(
                    f"Review and fix {finding.vuln_type.value} vulnerability in "
                    f"{finding.file_path}:{finding.line_number}. "
                    "Apply security best practices and input validation."
                ),
                code_snippet="# Review the code at the specified location and apply security fixes.",
                effort_estimate="2-4 hours",
                references=[
                    "https://owasp.org/www-project-top-ten/",
                    f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html"
                    if finding.cwe_id else "https://cwe.mitre.org/",
                ],
            )

        # Add context-specific notes
        if code_context:
            lang = code_context.get("language", "python")
            if lang != "python" and template:
                guidance.description += (
                    f"\n\nNote: Code snippets shown in Python. "
                    f"Adapt for {lang} using equivalent libraries."
                )

        logger.info(
            "Generated remediation for %s (%s) in %s",
            finding.vuln_type.value, priority.value, finding.file_path,
        )

        return guidance

    def _adjust_effort(self, base_effort: str, priority: TriagePriority) -> str:
        """Adjust effort estimate based on priority (urgent = immediate action)."""
        if priority == TriagePriority.URGENT:
            return f"{base_effort} (IMMEDIATE — drop current work)"
        elif priority == TriagePriority.HIGH:
            return f"{base_effort} (schedule within 24 hours)"
        elif priority == TriagePriority.MEDIUM:
            return f"{base_effort} (schedule within 1 week)"
        elif priority == TriagePriority.LOW:
            return f"{base_effort} (schedule in next sprint)"
        return f"{base_effort} (track for awareness)"
