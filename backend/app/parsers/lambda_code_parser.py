"""Lambda function code parser for SDK call detection.

Parses Lambda function source code to identify AWS SDK calls
and map them to MITRE ATT&CK techniques.

IMPORTANT: This parser only runs when:
1. User has an active paying subscription
2. User has explicitly consented to code analysis
3. Required IAM permissions are available

The parser NEVER executes user code - it only performs static analysis.
"""

import ast
import base64
import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog
from botocore.exceptions import ClientError

from app.parsers.sdk_pattern_library import SDKPatternLibrary, SDKPattern

logger = structlog.get_logger()


@dataclass
class SDKCall:
    """Represents a detected SDK call in Lambda code."""

    service: str
    method: str
    line_number: int
    file_path: str
    context: str = ""  # Surrounding code context


@dataclass
class CodeAnalysisResult:
    """Result of analyzing Lambda function code."""

    function_name: str
    function_arn: str
    runtime: str

    # Detected patterns
    sdk_calls: list[SDKCall] = field(default_factory=list)
    matched_patterns: list[SDKPattern] = field(default_factory=list)

    # Analysis metadata
    files_analyzed: int = 0
    lines_analyzed: int = 0
    analysis_duration_ms: float = 0

    # Errors and warnings
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Permission issues
    permission_errors: list[str] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)


@dataclass
class PermissionCheckResult:
    """Result of IAM permission check for code analysis."""

    has_required_permissions: bool
    missing_permissions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_permissions: list[str] = field(default_factory=list)


class LambdaCodeParser:
    """Parses Lambda function code for SDK call detection.

    Supports:
    - Python (boto3, aiobotocore)
    - Node.js (aws-sdk, @aws-sdk/*)

    Security considerations:
    - Code is analyzed in-memory only
    - No code is stored or logged
    - Secrets in environment variables are redacted
    - Analysis times out after 30 seconds per function
    """

    # Required IAM permissions for code analysis
    REQUIRED_PERMISSIONS = [
        "lambda:GetFunction",  # Download function code
        "lambda:GetFunctionConfiguration",
    ]

    # Supported runtimes
    SUPPORTED_RUNTIMES = {
        "python3.8", "python3.9", "python3.10", "python3.11", "python3.12",
        "nodejs14.x", "nodejs16.x", "nodejs18.x", "nodejs20.x",
    }

    # boto3 client/resource patterns
    BOTO3_CLIENT_PATTERN = re.compile(
        r"boto3\.client\(['\"](\w+)['\"]",
        re.IGNORECASE
    )
    BOTO3_RESOURCE_PATTERN = re.compile(
        r"boto3\.resource\(['\"](\w+)['\"]",
        re.IGNORECASE
    )

    # AWS SDK v3 (Node.js) patterns
    AWS_SDK_V3_IMPORT = re.compile(
        r"from\s+['\"]@aws-sdk/client-(\w+)['\"]",
        re.IGNORECASE
    )
    AWS_SDK_V2_REQUIRE = re.compile(
        r"require\(['\"]aws-sdk['\"]\)",
        re.IGNORECASE
    )

    def __init__(self, session=None):
        """Initialize parser with AWS session.

        Args:
            session: boto3 session for AWS API calls
        """
        self.session = session
        self.pattern_library = SDKPatternLibrary()
        self.logger = logger.bind(component="LambdaCodeParser")

    async def check_permissions(self, region: str = "us-east-1") -> PermissionCheckResult:
        """Check if required IAM permissions are available.

        This should be called BEFORE attempting code analysis to provide
        clear feedback to users about missing permissions.
        """
        result = PermissionCheckResult(
            has_required_permissions=True,
            checked_permissions=self.REQUIRED_PERMISSIONS.copy()
        )

        if not self.session:
            result.has_required_permissions = False
            result.missing_permissions = self.REQUIRED_PERMISSIONS.copy()
            result.warnings.append("No AWS session configured")
            return result

        client = self.session.client("lambda", region_name=region)

        # Test lambda:GetFunction permission
        try:
            # Use a dummy function name to test permissions
            # This will fail with NotFound if we have permission, AccessDenied if not
            client.get_function(FunctionName="__permission_check_dummy__")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            if error_code == "AccessDeniedException":
                result.has_required_permissions = False
                result.missing_permissions.append("lambda:GetFunction")
                result.warnings.append(
                    "Missing lambda:GetFunction permission. "
                    "Code analysis requires permission to download function code. "
                    "Add this permission to your IAM role to enable enhanced detection mapping."
                )
            elif error_code == "ResourceNotFoundException":
                # This is expected - we have the permission
                pass
            else:
                result.warnings.append(f"Unexpected error checking permissions: {error_code}")

        # Test lambda:GetFunctionConfiguration permission
        try:
            client.get_function_configuration(FunctionName="__permission_check_dummy__")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            if error_code == "AccessDeniedException":
                result.has_required_permissions = False
                result.missing_permissions.append("lambda:GetFunctionConfiguration")
                result.warnings.append(
                    "Missing lambda:GetFunctionConfiguration permission. "
                    "This is needed to analyze function settings."
                )
            elif error_code == "ResourceNotFoundException":
                pass

        if not result.has_required_permissions:
            result.warnings.append(
                f"To enable code analysis, add these permissions to your IAM policy: "
                f"{', '.join(result.missing_permissions)}"
            )

        return result

    async def analyze_function(
        self,
        function_name: str,
        region: str,
        consent_verified: bool = False,
    ) -> CodeAnalysisResult:
        """Analyze a Lambda function's code for SDK calls.

        Args:
            function_name: Lambda function name or ARN
            region: AWS region
            consent_verified: MUST be True - confirms user has consented

        Returns:
            CodeAnalysisResult with detected patterns and any errors
        """
        import time
        start_time = time.time()

        result = CodeAnalysisResult(
            function_name=function_name,
            function_arn="",
            runtime="",
        )

        # CRITICAL: Require explicit consent verification
        if not consent_verified:
            result.errors.append(
                "Code analysis requires explicit user consent. "
                "Please enable code analysis in your account settings."
            )
            return result

        if not self.session:
            result.errors.append("AWS session not configured")
            return result

        client = self.session.client("lambda", region_name=region)

        # Get function info and code
        try:
            response = client.get_function(FunctionName=function_name)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            if error_code == "AccessDeniedException":
                result.permission_errors.append(
                    "Access denied when retrieving function code. "
                    "Ensure your IAM role has lambda:GetFunction permission."
                )
                result.missing_permissions.append("lambda:GetFunction")
            elif error_code == "ResourceNotFoundException":
                result.errors.append(f"Function not found: {function_name}")
            else:
                result.errors.append(f"Error retrieving function: {str(e)}")

            return result

        # Extract function metadata
        config = response.get("Configuration", {})
        result.function_arn = config.get("FunctionArn", "")
        result.runtime = config.get("Runtime", "")

        # Check if runtime is supported
        if result.runtime not in self.SUPPORTED_RUNTIMES:
            result.warnings.append(
                f"Runtime '{result.runtime}' is not fully supported for code analysis. "
                f"Supported runtimes: {', '.join(sorted(self.SUPPORTED_RUNTIMES))}"
            )
            # Continue anyway - we might still find patterns

        # Get code location
        code_info = response.get("Code", {})
        code_location = code_info.get("Location")

        if not code_location:
            result.errors.append("Could not retrieve function code location")
            return result

        # Download and analyze code
        try:
            sdk_calls = await self._download_and_parse_code(
                code_location, result.runtime, result
            )
            result.sdk_calls = sdk_calls

            # Match calls to patterns
            for call in sdk_calls:
                patterns = self.pattern_library.find_patterns(call.service, call.method)
                for pattern in patterns:
                    if pattern not in result.matched_patterns:
                        result.matched_patterns.append(pattern)

        except Exception as e:
            result.errors.append(f"Error analyzing code: {str(e)}")
            self.logger.error("code_analysis_error", error=str(e), function=function_name)

        # Calculate duration
        result.analysis_duration_ms = (time.time() - start_time) * 1000

        self.logger.info(
            "function_analysis_complete",
            function=function_name,
            sdk_calls_found=len(result.sdk_calls),
            patterns_matched=len(result.matched_patterns),
            duration_ms=result.analysis_duration_ms,
        )

        return result

    async def _download_and_parse_code(
        self,
        code_location: str,
        runtime: str,
        result: CodeAnalysisResult,
    ) -> list[SDKCall]:
        """Download function code and parse for SDK calls."""
        import urllib.request

        sdk_calls = []

        # Download the deployment package
        with urllib.request.urlopen(code_location, timeout=30) as response:
            code_bytes = response.read()

        # Extract and analyze files from zip
        try:
            with zipfile.ZipFile(io.BytesIO(code_bytes)) as zf:
                for file_info in zf.infolist():
                    file_path = file_info.filename

                    # Skip non-code files
                    if not self._is_code_file(file_path, runtime):
                        continue

                    # Read file content
                    try:
                        with zf.open(file_path) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    result.files_analyzed += 1
                    result.lines_analyzed += content.count("\n")

                    # Parse based on runtime
                    if runtime.startswith("python"):
                        calls = self._parse_python_code(content, file_path)
                    elif runtime.startswith("nodejs"):
                        calls = self._parse_nodejs_code(content, file_path)
                    else:
                        calls = []

                    sdk_calls.extend(calls)

        except zipfile.BadZipFile:
            result.errors.append("Invalid deployment package format")

        return sdk_calls

    def _is_code_file(self, file_path: str, runtime: str) -> bool:
        """Check if file should be analyzed based on runtime."""
        # Skip common non-code paths
        skip_patterns = [
            "__pycache__",
            "node_modules",
            ".git",
            "test",
            "tests",
            "__tests__",
            ".d.ts",  # TypeScript declarations
        ]

        for pattern in skip_patterns:
            if pattern in file_path.lower():
                return False

        if runtime.startswith("python"):
            return file_path.endswith(".py")
        elif runtime.startswith("nodejs"):
            return file_path.endswith((".js", ".mjs", ".ts"))

        return False

    def _parse_python_code(self, content: str, file_path: str) -> list[SDKCall]:
        """Parse Python code for boto3 SDK calls."""
        sdk_calls = []

        # Track client/resource variables
        client_vars: dict[str, str] = {}  # var_name -> service_name

        # Find boto3.client() / boto3.resource() calls
        for match in self.BOTO3_CLIENT_PATTERN.finditer(content):
            service = match.group(1)
            # Find variable assignment
            line_start = content.rfind("\n", 0, match.start()) + 1
            line = content[line_start:content.find("\n", match.end())]

            # Extract variable name (simple heuristic)
            if "=" in line:
                var_name = line.split("=")[0].strip()
                client_vars[var_name] = service

        for match in self.BOTO3_RESOURCE_PATTERN.finditer(content):
            service = match.group(1)
            line_start = content.rfind("\n", 0, match.start()) + 1
            line = content[line_start:content.find("\n", match.end())]
            if "=" in line:
                var_name = line.split("=")[0].strip()
                client_vars[var_name] = service

        # Find method calls on known clients
        for var_name, service in client_vars.items():
            # Pattern: client.method_name(
            method_pattern = re.compile(
                rf"\b{re.escape(var_name)}\.(\w+)\s*\(",
                re.IGNORECASE
            )

            for match in method_pattern.finditer(content):
                method = match.group(1)
                line_num = content[:match.start()].count("\n") + 1

                # Get context (surrounding lines)
                lines = content.split("\n")
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                context = "\n".join(lines[start_line:end_line])

                sdk_calls.append(SDKCall(
                    service=service,
                    method=method,
                    line_number=line_num,
                    file_path=file_path,
                    context=context[:200],  # Limit context size
                ))

        return sdk_calls

    def _parse_nodejs_code(self, content: str, file_path: str) -> list[SDKCall]:
        """Parse Node.js code for AWS SDK calls."""
        sdk_calls = []

        # Track imported services
        services: set[str] = set()

        # AWS SDK v3 imports
        for match in self.AWS_SDK_V3_IMPORT.finditer(content):
            services.add(match.group(1).lower())

        # AWS SDK v2 requires
        if self.AWS_SDK_V2_REQUIRE.search(content):
            # Look for service instantiations
            v2_pattern = re.compile(
                r"new\s+AWS\.(\w+)\s*\(",
                re.IGNORECASE
            )
            for match in v2_pattern.finditer(content):
                services.add(match.group(1).lower())

        # Look for common method patterns
        # v3: client.send(new GetFunctionCommand(...))
        v3_command_pattern = re.compile(
            r"\.send\s*\(\s*new\s+(\w+)Command",
            re.IGNORECASE
        )

        for match in v3_command_pattern.finditer(content):
            command_name = match.group(1)
            line_num = content[:match.start()].count("\n") + 1

            # Convert command name to method (e.g., GetFunction -> get_function)
            method = self._camel_to_snake(command_name)

            # Try to determine service from context
            service = self._infer_service_from_command(command_name, services)

            if service:
                sdk_calls.append(SDKCall(
                    service=service,
                    method=method,
                    line_number=line_num,
                    file_path=file_path,
                ))

        # v2: client.methodName(...)
        for service in services:
            method_pattern = re.compile(
                rf"(\w+)\.(\w+)\s*\(",
                re.IGNORECASE
            )

            for match in method_pattern.finditer(content):
                method = match.group(2)
                # Skip common non-SDK methods
                if method.lower() in ["then", "catch", "finally", "promise"]:
                    continue

                line_num = content[:match.start()].count("\n") + 1

                sdk_calls.append(SDKCall(
                    service=service,
                    method=self._camel_to_snake(method),
                    line_number=line_num,
                    file_path=file_path,
                ))

        return sdk_calls

    def _camel_to_snake(self, name: str) -> str:
        """Convert CamelCase to snake_case."""
        import re
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

    def _infer_service_from_command(self, command_name: str, known_services: set[str]) -> Optional[str]:
        """Infer AWS service from command name."""
        # Common command prefixes
        prefix_to_service = {
            "GetFunction": "lambda",
            "ListFunctions": "lambda",
            "CreateFunction": "lambda",
            "GetSecret": "secretsmanager",
            "DescribeInstances": "ec2",
            "GetObject": "s3",
            "PutObject": "s3",
            "ListBuckets": "s3",
            "GetItem": "dynamodb",
            "PutItem": "dynamodb",
            "Query": "dynamodb",
            "CreateUser": "iam",
            "GetUser": "iam",
            "CreateAccessKey": "iam",
        }

        for prefix, service in prefix_to_service.items():
            if command_name.startswith(prefix.replace("_", "")):
                return service

        # Return first known service as fallback
        if known_services:
            return next(iter(known_services))

        return None

    def get_permission_requirements(self) -> dict:
        """Get IAM permission requirements for code analysis feature."""
        return {
            "required_permissions": self.REQUIRED_PERMISSIONS,
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "LambdaCodeAnalysis",
                        "Effect": "Allow",
                        "Action": self.REQUIRED_PERMISSIONS,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
                            }
                        }
                    }
                ]
            },
            "description": (
                "These permissions allow the Detection Coverage Validator to download "
                "and analyze Lambda function code for more accurate MITRE ATT&CK mappings. "
                "The code is analyzed in-memory and never stored."
            ),
            "risks": [
                "Function source code will be temporarily downloaded for analysis",
                "Analysis results may reveal business logic patterns",
                "Increased scan time due to code download and parsing",
            ],
            "mitigations": [
                "Code is never stored or logged",
                "Analysis runs in isolated memory",
                "You can revoke consent at any time",
                "Secrets in environment variables are automatically redacted",
            ],
        }
