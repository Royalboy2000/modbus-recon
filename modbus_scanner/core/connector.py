# modbus_scanner/core/connector.py
"""
Handles Modbus TCP connections.
"""
import asyncio
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ConnectionException
import logging

logger = logging.getLogger("rich") # Use the rich logger configured in main

class ModbusConnector:
    """
    Manages connection to a Modbus TCP server.
    """
    def __init__(self, host: str, port: int = 502, timeout: float = 1.0):
        """
        Initializes the ModbusConnector.

        :param host: The target host IP address.
        :param port: The target port (default is 502).
        :param timeout: Connection timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.client = None
        logger.debug(f"ModbusConnector initialized for {self.host}:{self.port} with timeout {self.timeout}s")

    async def connect(self) -> bool:
        """
        Establishes a connection to the Modbus TCP server.

        :return: True if connection is successful, False otherwise.
        """
        if self.client and self.client.is_active:
            logger.debug(f"Already connected to {self.host}:{self.port}")
            return True

        self.client = AsyncModbusTcpClient(self.host, port=self.port, timeout=self.timeout)
        logger.debug(f"Attempting to connect to {self.host}:{self.port}...")
        try:
            if await self.client.connect():
                logger.info(f"Successfully connected to Modbus server at [green]{self.host}:{self.port}[/green]")
                return True
            else:
                logger.warning(f"Failed to connect to Modbus server at [yellow]{self.host}:{self.port}[/yellow] (client.connect returned False)")
                self.client = None
                return False
        except ConnectionException as e:
            logger.warning(f"Connection failed for {self.host}:{self.port}: {e}")
            self.client = None
            return False
        except asyncio.TimeoutError:
            logger.warning(f"Connection timed out for {self.host}:{self.port} after {self.timeout}s")
            # Ensure client is cleaned up if connect() internally doesn't
            if self.client:
                await self.client.close()
            self.client = None
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during connection to {self.host}:{self.port}: {e}")
            if self.client:
                await self.client.close()
            self.client = None
            return False


    async def disconnect(self):
        """
        Closes the connection to the Modbus TCP server.
        """
        if self.client and self.client.is_active:
            logger.debug(f"Disconnecting from {self.host}:{self.port}")
            self.client.close() # For AsyncModbusTcpClient, close is synchronous but should be called
            # await self.client.close() # In some versions or if it becomes async
            logger.info(f"Disconnected from [green]{self.host}:{self.port}[/green]")
        self.client = None

    def get_client(self) -> AsyncModbusTcpClient | None:
        """
        Returns the active Modbus client.

        :return: The AsyncModbusTcpClient instance if connected, else None.
        """
        return self.client if self.client and self.client.is_active else None

# Example usage (for testing purposes, will be removed or moved to tests)
async def main_test():
    console = None
    try:
        from rich.console import Console
        console = Console()
        logging.basicConfig(level="DEBUG", format="%(message)s", handlers=[from rich.logging import RichHandler; RichHandler(console=console)])
    except ImportError:
        logging.basicConfig(level="DEBUG", format="%(asctime)s - %(levelname)s - %(message)s")


    # Replace with a real or simulated Modbus server IP for testing
    # For now, this will likely fail unless a server is at localhost
    test_host = "localhost"
    # test_host = "102.222.4.82" # Target from prompt - DO NOT RUN WITHOUT PERMISSION

    connector = ModbusConnector(host=test_host, port=502, timeout=2.0)
    if await connector.connect():
        logger.info("Connection successful. Client is active.")
        client = connector.get_client()
        if client:
            logger.info(f"Client details: {client}")
        await connector.disconnect()
    else:
        logger.error("Connection failed.")

if __name__ == "__main__":
    # This is just for quick testing of this module.
    # Run `python -m modbus_scanner.core.connector` from the project root.
    # You'll need a Modbus TCP server running on localhost:502 for the test to succeed.
    # A simple simulator like 'diagslave' can be used:
    # `diagslave -m tcp -p 502`
    asyncio.run(main_test())
