import asyncio

class BaseServerTest:
    def __init__(self, server_class, service_config, logger, bindaddr='127.0.0.1'):
        self.server_class = server_class
        self.service_config = service_config
        self.logger = logger
        self.bindaddr = bindaddr
        self.server_task = None
        self.server = None

    async def start_server(self):
        self.server = self.server_class(self.service_config, self.logger, bindaddr=self.bindaddr)
        self.server_task = asyncio.create_task(self.server.start())
        await asyncio.sleep(1)  # Give the server time to start

    async def stop_server(self):
        if self.server:
            await self.server.stop()
        if self.server_task:
            self.server_task.cancel()
            await self.server_task

    async def run_test(self):
        raise NotImplementedError("This method should be implemented by subclasses")