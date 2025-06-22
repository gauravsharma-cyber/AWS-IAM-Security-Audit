import boto3
import pandas as pd
from datetime import datetime, timezone
import botocore.exceptions
import sys

SENSITIVE_ACTIONS = [
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "iam:PassRole", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicy", "iam:UpdatePolicy", "*"
]

def check_aws_credentials():
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"? Authenticated as: {identity['Arn']}")
    except botocore.exceptions.NoCredentialsError:
        print("? AWS credentials not found. Please configure them via `aws configure` or environment variables.")
        sys.exit(1)
    except botocore.exceptions.ClientError as e:
        print(f"? AWS client error: {e}")
        sys.exit(1)

def check_privilege_escalation(policies):
    for policy in policies:
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                for sensitive in SENSITIVE_ACTIONS:
                    if sensitive.lower() in action.lower() or action == "*":
                        return True, action
    return False, None

def get_policy_documents(iam, username):
    documents = []
    inline = iam.list_user_policies(UserName=username)['PolicyNames']
    for name in inline:
        doc = iam.get_user_policy(UserName=username, PolicyName=name)
        documents.append(doc['PolicyDocument'])

    attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for p in attached:
        arn = p['PolicyArn']
        ver = iam.get_policy(PolicyArn=arn)['Policy']['DefaultVersionId']
        doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)['PolicyVersion']['Document']
        documents.append(doc)

    return documents

def audit_iam_users():
    iam = boto3.client('iam')
    data = []
    paginator = iam.get_paginator('list_users')
    for resp in paginator.paginate():
        for user in resp['Users']:
            name = user['UserName']
            created = user['CreateDate'].strftime('%Y-%m-%d')
            attached = [p['PolicyName'] for p in iam.list_attached_user_policies(UserName=name)['AttachedPolicies']]
            inline = iam.list_user_policies(UserName=name)['PolicyNames']
            keys = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
            mfa = iam.list_mfa_devices(UserName=name)['MFADevices']

            key_info = []
            for k in keys:
                age = (datetime.now(timezone.utc) - k['CreateDate']).days
                key_info.append(f"{k['AccessKeyId']} (Status: {k['Status']}, Age: {age}d)")

            docs = get_policy_documents(iam, name)
            has_escalation, action = check_privilege_escalation(docs)

            data.append({
                "UserName": name,
                "Created": created,
                "AttachedPolicies": ", ".join(attached),
                "InlinePolicies": ", ".join(inline),
                "AccessKeys": "; ".join(key_info) if key_info else "None",
                "MFAEnabled": "Yes" if mfa else "No",
                "PrivilegeEscalationRisk": f"Yes ({action})" if has_escalation else "No"
            })

    return pd.DataFrame(data)

if __name__ == "__main__":
    check_aws_credentials()
    df = audit_iam_users()
    df.to_excel("aws_iam_security_audit.xlsx", index=False)
    print("? IAM security audit complete. Output saved to aws_iam_security_audit.xlsx")