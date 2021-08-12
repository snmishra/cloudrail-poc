from __future__ import annotations

from cloudrail.knowledge.context.aws.apigateway.api_gateway_stage import (
    AccessLogsSettings,
    ApiGatewayStage,
)
from cloudrail.knowledge.context.aws.apigateway.rest_api_gw import (
    ApiGatewayType,
    RestApiGw,
)
from cloudrail.knowledge.context.aws.apigateway.rest_api_gw_policy import (
    RestApiGwPolicy,
)
from cloudrail.knowledge.context.aws.aws_environment_context import (
    AwsEnvironmentContext,
)
from pulumi_policy import ResourceValidationArgs
from utils import dataclass_from, ensure_resource_type


@ensure_resource_type("aws:apigateway/restApi:RestApi")
def make_rest_api_gw_context(
    args: ResourceValidationArgs, account_id: str, region: str
):
    rest_api_gw = RestApiGw(
        rest_api_gw_id="",  # TODO: Unknown at validation time, will it still work?
        api_gw_name=args.props["name"],
        api_gateway_type=ApiGatewayType(args.props["endpoint_configuration"].types),
        account=account_id,
        region=region,
    )
    context = AwsEnvironmentContext(rest_api_gw=[rest_api_gw])
    return context


@ensure_resource_type("aws:apigateway/restApiPolicy:RestApiPolicy")
def make_rest_api_gw_policy_context(
    args: ResourceValidationArgs, account_id: str, region: str
):
    rest_api_gw_policy = RestApiGwPolicy(
        rest_api_gw_id=args.props["rest_api_id"],
        raw_document=args.props["policy"],
        policy_statements=[],
        account=account_id,
    )
    context = AwsEnvironmentContext(rest_api_gw_policies=[rest_api_gw_policy])
    return context


@ensure_resource_type("aws:apigateway/stage:Stage")
def make_api_gateway_stage_context(
    args: ResourceValidationArgs, account_id: str, region: str
):
    if access_log_settings := args.props.get("access_log_settings"):
        access_logs = dataclass_from(AccessLogsSettings, access_log_settings)
    else:
        access_logs = None
    api_gateway_stage = ApiGatewayStage(
        api_gw_id=args.props["rest_api"],
        stage_name=args.props["stage_name"],
        xray_tracing_enabled=args.props.get("xray_tracing_enabled", False),
        access_logs=access_log_settings,
        account=account_id,
        region=region,
    )
    context = AwsEnvironmentContext(rest_api_stages=[api_gateway_stage])
    return context
