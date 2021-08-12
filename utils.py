from __future__ import annotations
from typing import List, Type, TypeVar, Union
from cloudrail_mapper.exceptions import InvalidResource
from functools import wraps

_D = TypeVar("_D")


def dataclass_from(klass: Type[_D], obj) -> _D:
    """Make a dataclass instance from a compatible non-dataclass object"""

    return klass(**{k: getattr(obj, k) for k in klass._FIELDS})  # type: ignore


def ensure_resource_type(resource_type: Union[str | List[str]]):
    """Decorator that checks that args.resource_type is the expected type"""

    def _ensure_resource_type_decorator(func):
        @wraps(func)
        def wrapper(args, *_args, **kwargs):
            if isinstance(resource_type, str) and args.resource_type != resource_type:
                raise InvalidResource(
                    f"Expected resource of type {resource_type}, got {args.resource_type}"
                )
            elif (
                isinstance(resource_type, list)
                and args.resource_type not in resource_type
            ):
                raise InvalidResource(
                    f"Expected resource to be one of types {resource_type}, got {args.resource_type}"
                )
            return func(args, *_args, **kwargs)

        return wrapper

    return _ensure_resource_type_decorator
