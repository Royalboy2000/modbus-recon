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
# The main_test() function and its call are removed to prevent syntax errors
# during import, as this file is not intended to be run directly anymore.
# For module-specific tests, use the unittest framework in the tests/ directory.
