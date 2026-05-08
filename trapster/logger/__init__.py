import logging

from .api import ApiLogger
from .base import BaseLogger
from .ecs import EcsLogger
from .factory import set_logger
from .file import FileLogger
from .json import JsonLogger
from .output import OutputLogger
from .redis import RedisLogger


logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)

__all__ = [
    "BaseLogger",
    "JsonLogger",
    "FileLogger",
    "RedisLogger",
    "ApiLogger",
    "EcsLogger",
    "OutputLogger",
    "set_logger",
]
