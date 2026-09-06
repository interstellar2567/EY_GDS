from config_scanner.checks import (
    check_s3_buckets,
    check_lambda_functions,
    check_api_gateways,
)


def scan_configuration(configuration):
    """
    Scan cloud/serverless configuration for security
    misconfigurations.

    Returns:
        list[Finding]: Security findings discovered by the scanner.
    """

    if not isinstance(configuration, dict):
        raise ValueError(
            "Configuration must be a dictionary"
        )

    findings = []

    s3_buckets = configuration.get(
        "s3_buckets",
        [],
    )

    lambda_functions = configuration.get(
        "lambda_functions",
        [],
    )

    api_gateways = configuration.get(
        "api_gateways",
        [],
    )

    if not isinstance(s3_buckets, list):
        raise ValueError(
            "s3_buckets must be a list"
        )

    if not isinstance(lambda_functions, list):
        raise ValueError(
            "lambda_functions must be a list"
        )

    if not isinstance(api_gateways, list):
        raise ValueError(
            "api_gateways must be a list"
        )

    findings.extend(
        check_s3_buckets(s3_buckets)
    )

    findings.extend(
        check_lambda_functions(lambda_functions)
    )

    findings.extend(
        check_api_gateways(api_gateways)
    )

    return findings