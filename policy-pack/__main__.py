from pprint import pp

import boto3
from cloudrail.knowledge.context.aliases_dict import AliasesDict
from cloudrail.knowledge.context.aws.aws_environment_context import (
    AwsEnvironmentContext,
)
from cloudrail.knowledge.context.aws.s3.s3_bucket import S3Bucket
from cloudrail.knowledge.context.aws.s3.s3_bucket_versioning import S3BucketVersioning
from cloudrail.knowledge.rules.aws.non_context_aware.ensure_s3_buckets_versioning_rule import (
    EnsureS3BucketsVersioningRule,
)
from cloudrail.knowledge.rules.base_rule import RuleResultType
from pulumi_aws import get_caller_identity
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
    StackValidationArgs,
    StackValidationPolicy,
)

DEFAULT_ACCOUNT = boto3.client("sts").get_caller_identity().get("Account")
DEFAULT_REGION = "us-east-1"


def s3_no_public_read_validator(
    args: ResourceValidationArgs, report_violation: ReportViolation
):
    if args.resource_type == "aws:s3/bucket:Bucket" and "acl" in args.props:
        acl = args.props["acl"]
        if acl == "public-read" or acl == "public-read-write":
            report_violation(
                "You cannot set public-read or public-read-write on an S3 bucket. "
                "Read more about ACLs here: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html",
                None,
            )


def cloudrail_validator(
    args: ResourceValidationArgs, report_violation: ReportViolation
):
    region: str = DEFAULT_REGION
    if args.provider is not None:
        region = args.provider.props.get("region", DEFAULT_REGION)
    if args.resource_type == "aws:s3/bucket:Bucket":
        # We only have bucket name and acl available during preview
        account_id = DEFAULT_ACCOUNT
        bucket = S3Bucket(
            account=account_id,
            bucket_name=args.props["bucket"],
            arn=args.props.get("arn", None),
            region=region,
            policy=args.props.get("policy", None),
        )
        bucket.versioning_data = S3BucketVersioning(
            account=account_id,
            bucket_name=args.props["bucket"],
            region=region,
            versioning=args.props.get("versioning", False)
            and args.props["versioning"].get("enabled", False),
        )
        context = AwsEnvironmentContext(s3_buckets=AliasesDict(bucket))
        rule = EnsureS3BucketsVersioningRule()
        result = rule.run(context, {})
        if result.status == RuleResultType.FAILED:
            report_violation(f"CloudRail rule failed: {rule.get_id()}", None)


s3_no_public_read = ResourceValidationPolicy(
    name="s3-no-public-read",
    description="Prohibits setting the publicRead or publicReadWrite permission on AWS S3 buckets.",
    validate=s3_no_public_read_validator,
)

s3_cloudrail = ResourceValidationPolicy(
    name="s3-cloudrail", description="Check cloudrail", validate=cloudrail_validator
)

PolicyPack(
    name="aws-python",
    enforcement_level=EnforcementLevel.MANDATORY,
    policies=[s3_no_public_read, s3_cloudrail],
)
