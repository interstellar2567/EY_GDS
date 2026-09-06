import boto3


def get_lambda_client():
    return boto3.client("lambda")


def get_iam_client():
    return boto3.client("iam")


def get_lambda_role(lambda_name):
    lambda_client = get_lambda_client()

    response = lambda_client.get_function(
        FunctionName=lambda_name
    )

    return response["Configuration"]["Role"]


def get_role_name(role_arn):
    return role_arn.split("/")[-1]


def get_inline_policies(role_name):
    iam = get_iam_client()

    response = iam.list_role_policies(
        RoleName=role_name
    )

    policies = []

    for policy_name in response["PolicyNames"]:

        policy_response = iam.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
        )

        policies.append({
            "name": policy_name,
            "document": policy_response["PolicyDocument"]
        })

    return policies


def get_managed_policies(role_name):
    iam = get_iam_client()

    response = iam.list_attached_role_policies(
        RoleName=role_name
    )

    return response["AttachedPolicies"]


def get_managed_policy_document(policy_arn):
    iam = get_iam_client()

    policy = iam.get_policy(
        PolicyArn=policy_arn
    )

    default_version_id = policy["Policy"]["DefaultVersionId"]

    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version_id
    )

    return version["PolicyVersion"]["Document"]


if __name__ == "__main__":

    lambda_name = input("Enter Lambda function name: ")

    role_arn = get_lambda_role(lambda_name)
    role_name = get_role_name(role_arn)

    print("\nLambda IAM role:")
    print(role_name)

    print("\nInline policies:")

    inline_policies = get_inline_policies(role_name)

    for policy in inline_policies:

        print(f"\nPolicy: {policy['name']}")
        print(policy["document"])

    print("\nManaged policies:")

    managed_policies = get_managed_policies(role_name)

    for policy in managed_policies:

        print(f"\nPolicy: {policy['PolicyName']}")
        print(f"ARN: {policy['PolicyArn']}")

        document = get_managed_policy_document(
            policy["PolicyArn"]
        )

        print(document)