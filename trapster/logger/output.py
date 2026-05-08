import asyncio
from datetime import datetime
import json
import logging

import httpx
import redis

from .base import BaseLogger
from .formatters import DefaultFormatter, EcsFormatter


class OutputLogger(BaseLogger):
    def __init__(
        self,
        node_id,
        output="terminal",
        event_format="default",
        output_kwargs=None,
        format_kwargs=None,
    ):
        super().__init__(node_id)
        self.output = output
        self.event_format = event_format
        self.output_kwargs = output_kwargs or {}
        self.format_kwargs = format_kwargs or {}
        self.file = None
        self.redis_client = None
        self.api_headers = None
        self.api_url = None
        self._formatter = self._build_formatter()
        self._setup_output()

    def _build_formatter(self):
        if self.event_format == "default":
            return DefaultFormatter()
        if self.event_format == "ecs":
            return EcsFormatter(node_id=self.node_id, **self.format_kwargs)
        raise ValueError(
            f"Unsupported format '{self.event_format}'. Supported formats: default, ecs."
        )

    def _setup_output(self):
        if self.output == "terminal":
            return
        if self.output == "file":
            logfile = self.output_kwargs.get("logfile", "/var/log/trapster-community.log")
            mode = self.output_kwargs.get("mode", "w+")
            self.file = open(logfile, mode)
            return
        if self.output == "api":
            self.api_url = self.output_kwargs.get("url")
            if not self.api_url:
                raise ValueError("Missing required 'url' for api output.")
            self.api_headers = self.output_kwargs.get("headers", {})
            return
        if self.output == "redis":
            host = self.output_kwargs.get("host", "localhost")
            port = self.output_kwargs.get("port", 6379)
            self.redis_client = redis.Redis(host=host, port=port)
            return
        raise ValueError(
            f"Unsupported output '{self.output}'. Supported outputs: terminal, file, api, redis."
        )

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
        if not event:
            return

        payload = self._formatter.format(event)
        if self.output == "terminal":
            logging.info(payload)
        elif self.output == "file":
            self._write_file(payload)
        elif self.output == "api":
            self._post_api(payload)
        elif self.output == "redis":
            self._write_redis(payload, event)

    def _write_file(self, payload):
        try:
            json.dump(payload, self.file)
            self.file.write("\n")
            self.file.flush()
        except IOError as e:
            logging.error(f"An error occurred while writing to the log file: {e}")

    def _post_api(self, payload):
        loop = asyncio.get_event_loop()
        loop.create_task(self._post_request(payload))

    async def _post_request(self, payload):
        return await asyncio.to_thread(self._post_request_threaded, payload)

    def _post_request_threaded(self, payload):
        with httpx.Client(headers=self.api_headers) as client:
            return client.post(self.api_url, json=payload, timeout=10)

    def _write_redis(self, payload, event):
        timestamp = event.get("timestamp")
        try:
            score = datetime.fromisoformat(timestamp).timestamp()
        except Exception:
            score = datetime.now().timestamp()
        self.redis_client.zadd("events", {json.dumps(payload): score})

    def __del__(self):
        if self.file:
            self.file.close()
