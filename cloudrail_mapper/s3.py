from __future__ import annotations
from typing import Literal

from cloudrail.knowledge.context.aliases_dict import AliasesDict
from cloudrail.knowledge.context.aws.aws_environment_context import (
    AwsEnvironmentContext,
)
from cloudrail.knowledge.context.aws.iam.policy import S3AccessPointPolicy
from cloudrail.knowledge.context.aws.s3.public_access_block_settings import (
    PublicAccessBlockLevel,
    PublicAccessBlockSettings,
)
from cloudrail.knowledge.context.aws.s3.s3_bucket import S3Bucket
from cloudrail.knowledge.context.aws.s3.s3_bucket_access_point import (
    S3BucketAccessPoint,
    S3BucketAccessPointNetworkOrigin,
    S3BucketAccessPointNetworkOriginType,
)
from cloudrail.knowledge.context.aws.s3.s3_bucket_encryption import S3BucketEncryption
from cloudrail.knowledge.context.aws.s3.s3_bucket_logging import S3BucketLogging
from cloudrail.knowledge.context.aws.s3.s3_bucket_object import S3BucketObject
from cloudrail.knowledge.context.aws.s3.s3_bucket_versioning import S3BucketVersioning
import pulumi_aws
from pulumi_aws.s3 import bucket_object
from pulumi_aws.s3.access_point import AccessPointArgs
from pulumi_aws.s3.get_bucket import GetBucketResult

from pulumi_policy import ResourceValidationArgs
from pulumi_policy.policy import ResourceValidationArgs

from .exceptions import InvalidResource


def make_s3_bucket_context(args: ResourceValidationArgs, account_id: str, region: str):
    RESOURCE_TYPE = "aws:s3/bucket:Bucket"
    if args.resource_type != RESOURCE_TYPE:
        raise InvalidResource(
            f"Expected resource of type {RESOURCE_TYPE}, got {args.resource_type}"
        )
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


class S3AccessPointValidationArgs(ResourceValidationArgs):
    resource_type: Literal["aws:s3/accessPoint:AccessPoint"]


def make_s3_access_point_context(
    args: S3AccessPointValidationArgs, account_id: str, region: str
):
    RESOURCE_TYPE = "aws:s3/accessPoint:AccessPoint"
    if args.resource_type != RESOURCE_TYPE:
        raise InvalidResource(f"Expected resource of type {RESOURCE_TYPE}")
    if args.props.get("netowrk_origin") == S3BucketAccessPointNetworkOriginType.VPC:

        network_origin = S3BucketAccessPointNetworkOrigin(
            access_type=args.props["network_origin"],
            vpc_id=args.props["vpc_configuration"].vpc_id,
        )
    else:
        network_origin = S3BucketAccessPointNetworkOrigin(
            access_type=S3BucketAccessPointNetworkOriginType.INTERNET, vpc_id=""
        )

    if policy := args.props.get("policy"):
        access_point_policy = S3AccessPointPolicy(
            account=args.props.get("account_id", account_id),
            region=region,
            access_point_name=args.props["name"],
            statements=[],
            raw_document=policy,
        )
    else:
        access_point_policy = None
    access_point = S3BucketAccessPoint(
        account=args.props.get("account_id", account_id),
        bucket_name=args.props["bucket"],
        arn=args.props["arn"],
        name=args.props["name"],
        region=region,
        policy=access_point_policy,
        network_origin=network_origin,
    )

    context = AwsEnvironmentContext(s3_bucket_access_points=[access_point])
    return context


class S3BucketObjectValidationArgs(ResourceValidationArgs):
    resource_type: Literal["aws:s3/bucketObject:BucketObject"]


def make_s3_bucket_object_context(
    args: S3AccessPointValidationArgs, account_id: str, region: str
):
    RESOURCE_TYPE = "aws:s3/bucketObject:BucketObject"
    if args.resource_type != RESOURCE_TYPE:
        raise InvalidResource(
            f"Expected resource of type {RESOURCE_TYPE}, got {args.resource_type}"
        )

    bucket_object = S3BucketObject(
        account=args.props.get("account_id", account_id),
        bucket_name=args.props["bucket"],
        region=region,
        key=args.props["key"],
        encrypted=args.props["bucket_key_enabled"],
    )

    context = AwsEnvironmentContext(s3_bucket_objects=[bucket_object])
    return context


class S3PublicAccessBlockValidationArgs(ResourceValidationArgs):
    resource_type: (
        Literal["aws:s3/accountPublicAccessBlock:AccountPublicAccessBlock"]
        | Literal["aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"]
    )


def make_s3_public_access_block_context(
    args: S3PublicAccessBlockValidationArgs, account_id: str, region: str
):
    RESOURCE_TYPES = {
        "aws:s3/accountPublicAccessBlock:AccountPublicAccessBlock",
        "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
    }
    if args.resource_type in RESOURCE_TYPES:
        raise InvalidResource(
            f"Expected resource type to be on of {RESOURCE_TYPES}, got {args.resource_type}"
        )

    if args.resource_type == "aws:s3/accountPublicAccessBlock:AccountPublicAccessBlock":
        block_setting = PublicAccessBlockSettings(
            access_level=PublicAccessBlockLevel.ACCOUNT,
            bucket_name_or_account_id=args.props.get("account_id", account_id),
            block_public_acls=args.props.get("block_public_acls", False),
            block_public_policy=args.props.get("block_public_policy", False),
            ignore_public_acls=args.props.get("ignore_public_acls", False),
            restrict_public_buckets=args.props.get("restrict_public_buckets", False),
            account=args.props.get("account_id", account_id),
            region=region,
        )
    else:
        block_setting = PublicAccessBlockSettings(
            access_level=PublicAccessBlockLevel.BUCKET,
            bucket_name_or_account_id=args.props["bucket"],
            block_public_acls=args.props.get("block_public_acls", False),
            block_public_policy=args.props.get("block_public_policy", False),
            ignore_public_acls=args.props.get("ignore_public_acls", False),
            restrict_public_buckets=args.props.get("restrict_public_buckets", False),
            account=args.props.get("account_id", account_id),
            region=region,
        )

    context = AwsEnvironmentContext(
        s3_public_access_block_settings_list=[block_setting]
    )
    return context
