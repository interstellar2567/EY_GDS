from common.finding import Finding


def check_s3_buckets(buckets):
    findings = []

    for bucket in buckets:
        name = bucket.get("name", "unknown-bucket")

        # Public bucket check
        if bucket.get("public", False):
            findings.append(
                Finding(
                    scanner="config_scanner",
                    severity="CRITICAL",
                    title="Public S3 bucket detected",
                    description=(
                        "The S3 bucket is configured for public access."
                    ),
                    resource=name,
                    recommendation=(
                        "Block public access unless public access is explicitly required."
                    ),
                    evidence="public=True",
                )
            )

        # Encryption check
        if not bucket.get("encryption_enabled", False):
            findings.append(
                Finding(
                    scanner="config_scanner",
                    severity="HIGH",
                    title="S3 bucket encryption is disabled",
                    description=(
                        "The S3 bucket does not have encryption enabled."
                    ),
                    resource=name,
                    recommendation=(
                        "Enable server-side encryption for the S3 bucket."
                    ),
                    evidence="encryption_enabled=False",
                )
            )

    return findings


def check_lambda_functions(functions):
    findings = []

    for function in functions:
        name = function.get("name", "unknown-function")

        # Logging check
        if not function.get("logging_enabled", False):
            findings.append(
                Finding(
                    scanner="config_scanner",
                    severity="MEDIUM",
                    title="Lambda logging is disabled",
                    description=(
                        "The Lambda function does not have logging enabled."
                    ),
                    resource=name,
                    recommendation=(
                        "Enable CloudWatch logging for monitoring and security investigation."
                    ),
                    evidence="logging_enabled=False",
                )
            )

        # Environment encryption check
        if not function.get(
            "environment_encryption_enabled",
            False,
        ):
            findings.append(
                Finding(
                    scanner="config_scanner",
                    severity="HIGH",
                    title="Lambda environment encryption is disabled",
                    description=(
                        "Lambda environment variables are not configured with encryption."
                    ),
                    resource=name,
                    recommendation=(
                        "Enable encryption for sensitive Lambda environment variables."
                    ),
                    evidence="environment_encryption_enabled=False",
                )
            )

    return findings


def check_api_gateways(api_gateways):
    findings = []

    for api in api_gateways:
        name = api.get("name", "unknown-api")

        # Authentication check
        authentication = api.get(
            "authentication",
            "NONE",
        )

        if str(authentication).upper() == "NONE":
            findings.append(
                Finding(
                    scanner="config_scanner",
                    severity="HIGH",
                    title="API Gateway has no authentication",
                    description=(
                        "The API Gateway endpoint does not require authentication."
                    ),
                    resource=name,
                    recommendation=(
                        "Configure an appropriate authentication or authorization mechanism."
                    ),
                    evidence="authentication=NONE",
                )
            )

    return findings