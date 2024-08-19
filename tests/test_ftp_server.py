import pytest
import asyncio
import aioftp
from trapster.modules.ftp import FtpHoneypot
from trapster.logger import JsonLogger
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.mark.asyncio
async def run_server():
    service_config = {
        'port': 2121,
        'banner': "Microsoft FTP Service"
    }
    server = FtpHoneypot(service_config, JsonLogger('trapster-1'), bindaddr='127.0.0.1')
    
    # Start the server
    await server.start()
    await asyncio.sleep(1)  # Give the server some time to start

    yield server

    # Stop the server after tests
    await server.stop()

@pytest.mark.asyncio
async def test_ftp_connection():
    run_server()
    client = aioftp.Client()
    while True:
        asyncio.sleep(1)
    try:
        await client.connect("127.0.0.1", 2121)
        response = await client.get_passive()
        welcome_message = response.decode()
        assert welcome_message == '220 Microsoft FTP Service'
    except Exception as e:
        logger.error(f"Error during FTP connection test: {e}")
        raise
    finally:
        await client.quit()
