

def check_action(action: str) -> tuple[str, str] | None:
    """
    Check an IAM action for dangerous permissions.

    Returns:
        A tuple containing severity and description,
        or None when the action is considered safe.
    """

    action = str(action).lower()

    if action == "*":
        return (
            "CRITICAL",
            "Wildcard IAM action grants unrestricted permissions.",
        )

    if action == "iam:*":
        return (
            "CRITICAL",
            "Full IAM permissions are granted.",
        )

    high_risk_actions = {
        "iam:createrole",
        "iam:attachrolepolicy",
        "iam:putrolepolicy",
        "iam:passrole",
    }

    if action in high_risk_actions:
        return (
            "HIGH",
            f"High-risk IAM action detected: {action}",
        )

    if action.endswith(":*"):
        return (
            "HIGH",
            f"Wildcard service permission detected: {action}",
        )

    return None


def check_resource(resource: str) -> tuple[str, str] | None:
    """
    Check whether an IAM statement grants access to every resource.
    """

    if str(resource) == "*":
        return (
            "MEDIUM",
            "IAM permission applies to all resources.",
        )

    return None