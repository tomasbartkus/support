import argparse
import boto3
import csv
import json
import logging
import sys


TRAIL_BUCKET_ACCOUNT_ROLE_POLICY_FILE_NAME = "trail_bucket_account_role_policy.json"


def main():
    logging_format = "%(asctime)s [%(levelname)-7s] %(message)s"
    logging_handlers = [logging.FileHandler("aws_organization.log", mode="a"), logging.StreamHandler(sys.stdout)]
    logging.basicConfig(level=logging.INFO, handlers=logging_handlers, format=logging_format)

    parser = argparse.ArgumentParser(description="AWS organization onboarding")
    parser.add_argument("--configure", required=True, choices=["organization", "trail-bucket-account"])
    parser.add_argument("--trail-name", required=True, default=None, type=str)
    parser.add_argument("--user-access-key-id", required=True, type=str)
    parser.add_argument("--user-secret-access-key", required=True, type=str)
    parser.add_argument("--role-name", default="Ermetic", type=str)
    arguments = parser.parse_args()

    logging.info(f"Configure {arguments.configure} starting")
    
    if arguments.configure == "organization":
        configure_organization(
            arguments.role_name,
            arguments.trail_name,
            arguments.user_access_key_id,
            arguments.user_secret_access_key)
    elif arguments.configure == "trail-bucket-account":
        configure_trail_bucket_account(
            arguments.role_name,
            arguments.user_access_key_id,
            arguments.user_secret_access_key)
    
    logging.info(f"Configure {arguments.configure} completed")
    

def configure_organization(role_name, trail_name, user_access_key_id, user_secret_access_key):
        valid_trails = []
        configure_organization_core(
            role_name,
            trail_name,
            user_access_key_id,
            user_secret_access_key,
            valid_trails)

        if not valid_trails:
            logging.error("Could not find any valid trails in AWS organization")
            return
            
        with open(TRAIL_BUCKET_ACCOUNT_ROLE_POLICY_FILE_NAME, mode="w") as trail_bucket_account_role_policy_file:
            trail_bucket_account_role_policy_file.write(get_trail_bucket_account_role_policy_document(valid_trails))

        logging.info(f"'{TRAIL_BUCKET_ACCOUNT_ROLE_POLICY_FILE_NAME}' created")


def configure_organization_core(role_name, trail_name, user_access_key_id, user_secret_access_key, valid_trails):
    initial_account_session = boto3.Session(user_access_key_id, user_secret_access_key)

    initial_account_sts_client = initial_account_session.client("sts")
    get_caller_identity_response = initial_account_sts_client.get_caller_identity()
    initial_account_id = get_caller_identity_response["Account"]

    initial_account_organizations_client = initial_account_session.client("organizations")

    try:
        describe_organization_response = initial_account_organizations_client.describe_organization()
    except initial_account_organizations_client.exceptions.AWSOrganizationsNotInUseException:
        logging.error(f"AWS account {initial_account_id} is not a member of an AWS organization")
        return

    if describe_organization_response["Organization"]["MasterAccountId"] != initial_account_id:
        logging.error(f"AWS account {initial_account_id} is not the master account of the AWS organization")
        return

    with open("trails.csv", mode="w") as trails_file:
        trails_file_csv_writer = \
            csv.DictWriter(
                trails_file,
                fieldnames=[
                    "AccountId",
                    "Name",
                    "TrailARN",
                    "Enabled",
                    "S3BucketName",
                    "S3KeyPrefix",
                    "SnsTopicName",
                    "SnsTopicARN",
                    "IncludeGlobalServiceEvents",
                    "IsMultiRegionTrail",
                    "HomeRegion",
                    "LogFileValidationEnabled",
                    "CloudWatchLogsLogGroupArn",
                    "CloudWatchLogsRoleArn",
                    "KmsKeyId",
                    "HasCustomEventSelectors",
                    "HasInsightSelectors",
                    "IsOrganizationTrail",
                    "EventSelectors"
                ])
        trails_file_csv_writer.writeheader()

        list_accounts_response = initial_account_organizations_client.list_accounts()
        for account in list_accounts_response["Accounts"]:
            account_id = account["Id"]

            if describe_organization_response["Organization"]["MasterAccountId"] == account_id:
                account_session = initial_account_session
            else:
                try:
                    assume_role_response = initial_account_sts_client.assume_role(
                        RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
                        RoleSessionName="Ermetic")
                    assumed_role_credentials = assume_role_response["Credentials"]
                    account_session = boto3.Session(
                        assumed_role_credentials["AccessKeyId"],
                        assumed_role_credentials["SecretAccessKey"],
                        assumed_role_credentials["SessionToken"])
                except:
                    logging.warning(f"AWS account {account_id} is missing the OrganizationAccountAccessRole role or it cannot be assumed")
                    logging.warning("See role creation instructions: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html#orgs_manage_accounts_create-cross-account-role")
                    continue

            try:
                configure_analyzed_account(
                    account_id,
                    account_session,
                    role_name)
            except Exception as exception:
                logging.warning(f"AWS account {account_id} configuration failed. Exception:{exception}")

            try:
                write_account_trails(
                    account_id,
                    account_session,
                    trails_file_csv_writer,
                    trail_name,
                    valid_trails)
            except Exception as exception:
                logging.warning(f"AWS account {account_id} failed to retrieve trails info. Exception:{exception}")


def configure_analyzed_account(account_id, account_session, role_name):
    configure_account(
        account_id,
        account_session,
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Action": [
                    "autoscaling:Describe*",
                    "batch:Describe*",
                    "batch:List*",
                    "cloudformation:Describe*",
                    "cloudformation:List*",
                    "cloudtrail:Describe*",
                    "cloudtrail:Get*",
                    "cloudtrail:List*",
                    "cloudtrail:LookupEvents",
                    "cloudwatch:Describe*",
                    "cloudwatch:GetMetric*",
                    "cloudwatch:ListMetrics",
                    "config:Describe*",
                    "dynamodb:Describe*",
                    "dynamodb:List*",
                    "ec2:Describe*",
                    "ecr:Describe*",
                    "ecr:GetRepositoryPolicy",
                    "ecr:List*",
                    "ecs:Describe*",
                    "ecs:List*",
                    "eks:Describe*",
                    "eks:List*",
                    "elasticache:Describe*",
                    "elasticache:List*",
                    "elasticbeanstalk:Describe*",
                    "elasticbeanstalk:List*",
                    "elasticloadbalancing:Describe*",
                    "es:Describe*",
                    "es:List*",
                    "glacier:Describe*",
                    "glacier:Get*",
                    "glacier:List*",
                    "iam:Generate*",
                    "iam:Get*",
                    "iam:List*",
                    "kms:Describe*",
                    "kms:GetKey*",
                    "kms:List*",
                    "lambda:Get*Policy",
                    "lambda:List*",
                    "logs:Describe*",
                    "organizations:Describe*",
                    "organizations:List*",
                    "redshift:Describe*",
                    "redshift:List*",
                    "rds:Describe*",
                    "rds:List*",
                    "s3:Describe*",
                    "s3:GetAccessPoint*",
                    "s3:GetAccountPublicAccessBlock",
                    "s3:GetBucket*",
                    "s3:GetEncryptionConfiguration",
                    "s3:ListAccessPoints",
                    "s3:ListAllMyBuckets",
                    "s3:ListBucketVersions",
                    "s3:ListJobs",
                    "secretsmanager:Describe*",
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:List*",
                    "sns:List*",
                    "ssm:Describe*",
                    "ssm:List*",
                    "tag:Get*"
                ],
                "Resource": "*"
                },
                {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": "arn:aws:s3:::elasticbeanstalk-*"
                }
            ]
        }),
        "ReadOnly",
        "arn:aws:iam::aws:policy/SecurityAudit",
        role_name)


def configure_trail_bucket_account(role_name, user_access_key_id, user_secret_access_key):
    trail_bucket_account_session = boto3.Session(user_access_key_id, user_secret_access_key)
    trail_bucket_account_sts_client = trail_bucket_account_session.client("sts")
    get_caller_identity_response = trail_bucket_account_sts_client.get_caller_identity()
    trail_bucket_account_id = get_caller_identity_response["Account"]

    with open(TRAIL_BUCKET_ACCOUNT_ROLE_POLICY_FILE_NAME, mode="r") as trail_bucket_account_role_policy_file:
        trail_bucket_account_role_policy_document = trail_bucket_account_role_policy_file.read()
        configure_account(
            trail_bucket_account_id,
            trail_bucket_account_session,
            trail_bucket_account_role_policy_document,
            "TrailBucketReadOnly",
            None,
            role_name)


def configure_account(account_id, account_session, inline_policy_document, inline_policy_name, managed_policy_arn, role_name):
    account_iam_client = account_session.client("iam")
    role_assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {
                    "AWS": "arn:aws:iam::081802104111:root"
                }
            }
        ]
    })

    try:
        account_iam_client.get_role(RoleName=role_name)
        account_iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=role_assume_role_policy_document)
        logging.info(f"AWS account {account_id} role exists, assume role policy updated")
    except account_iam_client.exceptions.NoSuchEntityException:
        account_iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=role_assume_role_policy_document)
        logging.info(f"AWS account {account_id} role created")

    account_iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=inline_policy_document)
    logging.info(f"AWS account {account_id} role inline policy updated")

    if managed_policy_arn:
        account_iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=managed_policy_arn)
        logging.info(f"AWS account {account_id} role SecurityAudit policy attached")


def write_account_trails(account_id, account_session, trails_file_csv_writer, trail_name, valid_trails):
    account_cloudtrail_client = account_session.client("cloudtrail", "us-east-2")
    describe_trails_response = account_cloudtrail_client.describe_trails()
    trail_valid = False
    for trail in describe_trails_response["trailList"]:
        get_event_selectors_response = account_cloudtrail_client.get_event_selectors(TrailName=trail["TrailARN"])
        get_trail_status_response = account_cloudtrail_client.get_trail_status(Name=trail["TrailARN"])

        trail_enabled = get_trail_status_response["IsLogging"]
        trail_event_selectors = get_event_selectors_response["EventSelectors"]

        trails_file_csv_writer.writerow({
            **trail,
            "AccountId" : account_id,
            "Enabled" : trail_enabled,
            "EventSelectors" : trail_event_selectors,
        })

        trail_event_selectors_valid = False
        for trail_event_selector in trail_event_selectors:
            if trail_event_selector["ReadWriteType"] == "All" and trail_event_selector["IncludeManagementEvents"]:
                trail_event_selectors_valid = True

        if trail_enabled and \
           trail_event_selectors_valid and \
           trail["IncludeGlobalServiceEvents"] and \
           trail["IsMultiRegionTrail"] and \
           trail["LogFileValidationEnabled"] and \
           trail["Name"] == trail_name:
            valid_trails.append(trail)
            trail_valid = True

    if not trail_valid:
        logging.warning(f"AWS account {account_id} could not find valid trail")


def get_trail_bucket_account_role_policy_document(trails):
    trail_bucket_arns = list(set(f"arn:aws:s3:::{trail['S3BucketName']}" for trail in trails))
    trail_key_arns = list(set(trail["KmsKeyId"] for trail in trails))

    trail_bucket_account_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": sum([[trail_bucket_arn, f"{trail_bucket_arn}/*"] for trail_bucket_arn in trail_bucket_arns], [])
            }
        ]
    }

    if trail_key_arns:
        trail_bucket_account_role_policy_document["Statement"].append({
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": trail_key_arns
        })

    return json.dumps(trail_bucket_account_role_policy_document)


if __name__ == "__main__":
    main()
