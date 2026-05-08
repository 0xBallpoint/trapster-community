import logging

from .api import ApiLogger
from .ecs import EcsLogger
from .file import FileLogger
from .json import JsonLogger
from .output import OutputLogger
from .redis import RedisLogger


def set_logger(config):
    node_id = config.get("id")
    try:
        logger_cfg = config.get("logger", {})
        logger_name = logger_cfg.get("name")

        if logger_name is not None:
            allowed_loggers = {
                "JsonLogger": JsonLogger,
                "FileLogger": FileLogger,
                "RedisLogger": RedisLogger,
                "ApiLogger": ApiLogger,
                "EcsLogger": EcsLogger,
            }

            logger_class = allowed_loggers.get(logger_name, None)
            kwargs = logger_cfg.get("kwargs", {})
            if logger_class is None:
                raise ValueError(f"Unsupported logger type: {logger_name}")

            try:
                logger = logger_class(node_id, **kwargs)
            except Exception as e:
                logging.error(f"[-] Invalid logger: {e}")
                return
        elif logger_cfg.get("output"):
            kwargs = logger_cfg.get("kwargs", {})
            output_kwargs = kwargs.get("output_kwargs")
            format_kwargs = kwargs.get("format_kwargs")

            # Convenience: allow flat kwargs for output and format settings.
            if output_kwargs is None:
                output_kwargs = {}
                for key in ("logfile", "mode", "url", "headers", "host", "port"):
                    if key in kwargs:
                        output_kwargs[key] = kwargs[key]

            if format_kwargs is None:
                format_kwargs = {}
                for key in ("service_version", "environment", "host_name", "observer_name", "ecs_version"):
                    if key in kwargs:
                        format_kwargs[key] = kwargs[key]

            logger = OutputLogger(
                node_id=node_id,
                output=logger_cfg.get("output", "terminal"),
                event_format=logger_cfg.get("format", "default"),
                output_kwargs=output_kwargs,
                format_kwargs=format_kwargs,
            )
            logger_name = f"{logger_cfg.get('format', 'default')}->{logger_cfg.get('output', 'terminal')}"
        else:
            raise TypeError

        logging.info(f"Using logger type: {logger_name} ")

    except Exception:
        logging.info("Defaulting to logger type: JsonLogger")
        return JsonLogger(node_id)

    return logger
