from __future__ import annotations

from cloudrail.knowledge.context.aliases_dict import AliasesDict
from cloudrail.knowledge.context.aws.aws_environment_context import (
    AwsEnvironmentContext,
)
from cloudrail.knowledge.context.aws.s3.s3_bucket import S3Bucket
from cloudrail.knowledge.context.aws.s3.s3_bucket_encryption import S3BucketEncryption
from cloudrail.knowledge.context.aws.s3.s3_bucket_logging import S3BucketLogging
from cloudrail.knowledge.context.aws.s3.s3_bucket_versioning import S3BucketVersioning
from cloudrail.knowledge.rules.aws.non_context_aware.ensure_s3_buckets_versioning_rule import (
    EnsureS3BucketsVersioningRule,
)
from cloudrail.knowledge.rules.base_rule import RuleResultType
from pulumi_aws import get_caller_identity, s3
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
    StackValidationArgs,
    StackValidationPolicy,
)
from pulumi_policy.policy import ResourceValidationArgs

from .exceptions import InvalidResource


def make_s3_bucket_context(args: ResourceValidationArgs, account_id: str, region: str):
    RESOURCE_TYPE = "aws:s3/bucket:Bucket"
    if args.resource_type != RESOURCE_TYPE:
        raise InvalidResource(f"Expected resource of type {RESOURCE_TYPE}")
    bucket = S3Bucket(
        account=account_id,
        bucket_name=args.props["bucket"],
        arn=args.props.get("arn", None),
        region=region,
        policy=args.props.get("policy", None),
    )
    s3_bucket_versioning = S3BucketVersioning(
        account=account_id,
        bucket_name=args.props["bucket"],
        region=region,
        versioning=args.props.get("versioning", False)
        and args.props["versioning"].get("enabled", False),
    )
    # Is this necessary when running in real CloudRail?
    bucket.versioning_data = s3_bucket_versioning

    # Add logging
    loggings = getattr(args.props, "loggings", None)
    # Not sure if this needs to be awaited?
    s3_bucket_loggings: list[S3BucketLogging] | None = None
    if loggings is not None:
        s3_bucket_loggings = [
            S3BucketLogging(
                bucket_name=args.props["bucket"],
                account=account_id,
                region=region,
                target_bucket=item.target_bucket,
                target_prefix=item.target_prefix,
            )
            for item in loggings
        ]
        bucket.bucket_logging = s3_bucket_loggings[0]

    # Add encryption
    encryption = getattr(args, "server_side_encryption_configuration", None)
    s3_bucket_encryption: list[S3BucketEncryption] | None = None
    if encryption is not None:
        s3_bucket_encryption = [
            S3BucketEncryption(
                bucket_name=args.props["bucket"],
                account=account_id,
                region=region,
                encrypted=True,
            )
        ]
        bucket.encryption_data = s3_bucket_encryption[0]

    context = AwsEnvironmentContext(
        s3_buckets=AliasesDict(bucket),
        s3_bucket_versioning=[s3_bucket_versioning],
        s3_bucket_encryption=s3_bucket_encryption,
        s3_bucket_logs=s3_bucket_loggings,
    )
    return context
