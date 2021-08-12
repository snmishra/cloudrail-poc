from __future__ import annotations

from typing import Literal, Optional, Sequence, cast

from cloudrail.knowledge.context.aliases_dict import AliasesDict
from cloudrail.knowledge.context.aws.aws_environment_context import (
    AwsEnvironmentContext,
)
from cloudrail.knowledge.context.aws.iam.policy import S3AccessPointPolicy
from cloudrail.knowledge.context.aws.networking_config.network_configuration import (
    NetworkConfiguration,
)
from cloudrail.knowledge.context.aws.s3outposts.s3outpost_endpoint import (
    S3OutpostEndpoint,
)

from pulumi_policy import ResourceValidationArgs
from pulumi_policy.policy import ResourceValidationArgs
from pulumi_aws.s3.outputs import BucketGrant, BucketServerSideEncryptionConfiguration

from .exceptions import InvalidResource


class S3OutpostEndpointValidationArgs(ResourceValidationArgs):
    resource_type: Literal["aws:s3outposts/endpoint:Endpoint"]


def make_s3outpost_endpoint_context(
    args: S3OutpostEndpointValidationArgs, account_id: str, region: str
):
    RESOURCE_TYPE = "aws:s3outposts/endpoint:Endpoint"
    if args.resource_type != RESOURCE_TYPE:
        raise InvalidResource(f"Expected resource of type {RESOURCE_TYPE}")
    arn = args.props["arn"]
    security_group_id = args.props["security_group_id"]
    subnet_id = args.props["subnet_id"]
    # TODO: how to get assign_public_ip for creating NetworkConfiguration object?
    vpc_config = NetworkConfiguration()
    endpoint = S3OutpostEndpoint(
        outpost_id=args.props["outpost_id"],
        arn=args.props["arn"],
        vpc_config=vpc_config,
        account=args.props.get("account_id", account_id),
        region=region,
    )

    context = AwsEnvironmentContext(s3outpost_endpoints=[endpoint])
    return context
