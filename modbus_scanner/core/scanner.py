# modbus_scanner/core/scanner.py
"""
Core scanning logic for Modbus devices.
Handles function code execution, data reading, and basic error handling.
"""
import asyncio
import logging
from typing import Optional, List, Tuple, Dict, Any

from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusIOException, ModbusException
from pymodbus.pdu import ExceptionResponse

logger = logging.getLogger("rich") # Use the rich logger

# Define common function codes
FC_READ_COILS = 1
FC_READ_DISCRETE_INPUTS = 2
FC_READ_HOLDING_REGISTERS = 3
FC_READ_INPUT_REGISTERS = 4
# FC_WRITE_SINGLE_COIL = 5 # Not typically used for recon
# FC_WRITE_SINGLE_REGISTER = 6 # Not typically used for recon
# FC_WRITE_MULTIPLE_COILS = 15 # Not typically used for recon
# FC_WRITE_MULTIPLE_REGISTERS = 16 # Not typically used for recon
# FC_READ_DEVICE_IDENTIFICATION = 43 # MEI Type 14 - for fingerprinting

SUPPORTED_FUNCTION_CODES = [
    FC_READ_COILS,
    FC_READ_DISCRETE_INPUTS,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
]

# Max registers/coils to read in a single request
# Modbus PDU limit is 253 bytes.
# For registers (2 bytes each), max is ~125. For coils (1 bit each, packed), max is ~2000.
# Let's be conservative to avoid issues.
MAX_READ_COUNT_REGISTERS = 100 # Max 100 registers (200 bytes)
MAX_READ_COUNT_COILS = 800    # Max 800 coils (100 bytes)


class ModbusScanner:
    """
    Performs scanning operations on a connected Modbus client.
    """

    def __init__(self, client: AsyncModbusTcpClient, unit_id: int, default_timeout: float = 1.0):
        """
        Initializes the ModbusScanner.

        :param client: An active AsyncModbusTcpClient instance.
        :param unit_id: The Modbus unit ID to target.
        :param default_timeout: Default timeout for individual Modbus requests.
        """
        self.client = client
        self.unit_id = unit_id
        self.default_timeout = default_timeout # Not directly used by client calls here, but good for reference
                                             # The client itself is configured with a timeout.
        if not self.client or not self.client.is_active:
            raise ValueError("Modbus client is not connected or invalid.")
        logger.debug(f"ModbusScanner initialized for Unit ID {self.unit_id}")

    async def _execute_read_request(self, fc: int, address: int, count: int) -> Optional[Any]:
        """
        Helper to execute a read request with timeout and error handling.
        """
        response = None
        try:
            logger.debug(f"Unit {self.unit_id}: Reading FC{fc} @ Address {address}, Count {count}")
            if fc == FC_READ_COILS:
                response = await self.client.read_coils(address, count, slave=self.unit_id)
            elif fc == FC_READ_DISCRETE_INPUTS:
                response = await self.client.read_discrete_inputs(address, count, slave=self.unit_id)
            elif fc == FC_READ_HOLDING_REGISTERS:
                response = await self.client.read_holding_registers(address, count, slave=self.unit_id)
            elif fc == FC_READ_INPUT_REGISTERS:
                response = await self.client.read_input_registers(address, count, slave=self.unit_id)
            else:
                logger.warning(f"Unit {self.unit_id}: Unsupported function code {fc} requested in _execute_read_request.")
                return None

            if response.isError():
                if isinstance(response, ExceptionResponse):
                    logger.warning(f"Unit {self.unit_id}: Modbus Exception on FC{fc} @ {address} "
                                   f"(Code: {response.exception_code}, Original Code: {response.original_code}, Value: {response.value})")
                else:
                    logger.warning(f"Unit {self.unit_id}: Modbus Error/Exception on FC{fc} @ {address}: {response}")
                return response # Return the error response for further analysis
            return response

        except ModbusIOException as e:
            logger.error(f"Unit {self.unit_id}: Modbus IO Exception during FC{fc} @ {address}: {e}")
            return None # Or a specific error indicator
        except asyncio.TimeoutError:
            logger.warning(f"Unit {self.unit_id}: Timeout during FC{fc} @ {address} (count: {count})")
            return None
        except Exception as e:
            logger.error(f"Unit {self.unit_id}: Unexpected error during FC{fc} @ {address}: {e}")
            return None


    async def check_function_code_support(self) -> Dict[int, bool]:
        """
        Checks basic support for FC 1, 2, 3, 4 by trying to read a single element.

        :return: A dictionary mapping function codes to a boolean indicating support.
        """
        fc_support = {}
        for fc in SUPPORTED_FUNCTION_CODES:
            # Try reading a single coil/register at address 0
            # This is a common way to check if the FC is generally supported
            # Some devices might not have address 0, but will return "Illegal Data Address"
            # rather than "Illegal Function" if the FC itself is okay.
            count = 1
            response = await self._execute_read_request(fc, address=0, count=count)

            if response is None: # Timeout or critical error
                fc_support[fc] = False
            elif response.isError():
                if isinstance(response, ExceptionResponse) and response.exception_code == 1: # Illegal Function
                    fc_support[fc] = False
                else:
                    # Any other error (like Illegal Data Address) or a valid response means the FC is likely supported
                    fc_support[fc] = True
            else: # Valid response
                fc_support[fc] = True
            logger.debug(f"Unit {self.unit_id}: FC{fc} support: {fc_support[fc]}")
        return fc_support

    async def read_coils(self, address: int, count: int) -> Optional[List[bool]]:
        """Reads coil status (FC1)."""
        response = await self._execute_read_request(FC_READ_COILS, address, count)
        if response and not response.isError():
            return response.bits[:count] # Ensure we only return the number of bits requested
        return None

    async def read_discrete_inputs(self, address: int, count: int) -> Optional[List[bool]]:
        """Reads discrete input status (FC2)."""
        response = await self._execute_read_request(FC_READ_DISCRETE_INPUTS, address, count)
        if response and not response.isError():
            return response.bits[:count]
        return None

    async def read_holding_registers(self, address: int, count: int) -> Optional[List[int]]:
        """Reads holding registers (FC3)."""
        response = await self._execute_read_request(FC_READ_HOLDING_REGISTERS, address, count)
        if response and not response.isError():
            return response.registers
        return None

    async def read_input_registers(self, address: int, count: int) -> Optional[List[int]]:
        """Reads input registers (FC4)."""
        response = await self._execute_read_request(FC_READ_INPUT_REGISTERS, address, count)
        if response and not response.isError():
            return response.registers
        return None

    # Placeholder for adaptive scanning and data dumping logic
    async def discover_valid_ranges_and_dump(self, fc: int, max_addr: int = 9999) -> Dict[str, Any]:
        """
        Attempts to discover valid register/coil ranges and dump their data.
        This is a very basic placeholder. Real adaptive scanning will be more complex.

        :param fc: Function code to scan.
        :param max_addr: Maximum address to check.
        :return: Dictionary with results.
        """
        logger.info(f"Unit {self.unit_id}: Starting adaptive scan for FC{fc} up to address {max_addr}")
        results = {"fc": fc, "unit_id": self.unit_id, "data": [], "errors": []}

        # Simplified scanning logic for now
        # A real implementation would be more adaptive, adjusting count and handling exceptions
        read_count = MAX_READ_COUNT_COILS if fc in [FC_READ_COILS, FC_READ_DISCRETE_INPUTS] else MAX_READ_COUNT_REGISTERS

        current_address = 0
        while current_address <= max_addr:
            response = await self._execute_read_request(fc, current_address, read_count)
            if response is None: # Timeout or major error
                logger.warning(f"Unit {self.unit_id}: Assuming end of readable range for FC{fc} at {current_address} due to timeout/error.")
                results["errors"].append({"address": current_address, "type": "timeout/comms_error"})
                break

            if response.isError():
                if isinstance(response, ExceptionResponse):
                    if response.exception_code == 2: # Illegal Data Address
                        logger.info(f"Unit {self.unit_id}: FC{fc} - Illegal Data Address at {current_address}. Trying smaller chunks or stopping block.")
                        # This is where adaptive logic would shrink read_count or step back.
                        # For now, we just stop this block.
                        # A more advanced scanner might try reading single registers to find sparse data.
                        if read_count == 1: # Was already trying smallest chunk
                             results["errors"].append({"address": current_address, "type": "illegal_data_address", "code": response.exception_code})
                             current_address += 1 # Try next single address
                             continue
                        else: # Try reducing read_count
                            read_count = max(1, read_count // 2) # Halve the count, ensure at least 1
                            logger.debug(f"Unit {self.unit_id}: FC{fc} - Reduced read count to {read_count} for address {current_address}")
                            # Don't increment current_address, retry with smaller count
                            continue


                    elif response.exception_code == 1: # Illegal Function
                        logger.warning(f"Unit {self.unit_id}: FC{fc} - Illegal Function at {current_address}. Stopping scan for this FC.")
                        results["errors"].append({"address": current_address, "type": "illegal_function", "code": response.exception_code})
                        return results # Stop scan for this FC
                    else:
                        logger.warning(f"Unit {self.unit_id}: FC{fc} - Modbus Exception {response.exception_code} at {current_address}. Skipping block.")
                        results["errors"].append({"address": current_address, "type": "modbus_exception", "code": response.exception_code})
                        # Potentially skip this block or try smaller reads
                else:
                    logger.warning(f"Unit {self.unit_id}: FC{fc} - Generic Modbus error at {current_address}. Skipping block.")
                    results["errors"].append({"address": current_address, "type": "generic_error"})

                current_address += read_count # Move to next block even on error (unless it's an error we adapt to by retrying)
                read_count = MAX_READ_COUNT_COILS if fc in [FC_READ_COILS, FC_READ_DISCRETE_INPUTS] else MAX_READ_COUNT_REGISTERS # Reset read_count

            else: # Successful read
                data = None
                actual_count = 0
                if fc == FC_READ_COILS or fc == FC_READ_DISCRETE_INPUTS:
                    data = response.bits
                    actual_count = len(response.bits) # pymodbus might return more than requested, up to byte boundary
                elif fc == FC_READ_HOLDING_REGISTERS or fc == FC_READ_INPUT_REGISTERS:
                    data = response.registers
                    actual_count = len(response.registers)

                if data:
                    # We need to ensure we only take 'read_count' items from the start of the block
                    # because the device might return less than 'read_count' if we are near the end of its address space.
                    # The 'actual_count' is what the device returned. 'read_count' is what we asked for.
                    # The number of valid items is min(actual_count, read_count).
                    num_valid_items = min(actual_count, read_count)
                    valid_data = data[:num_valid_items]

                    logger.info(f"Unit {self.unit_id}: FC{fc} @ {current_address}-{current_address + num_valid_items - 1} -> Read {num_valid_items} items.")
                    results["data"].append({
                        "start_address": current_address,
                        "values": valid_data
                    })
                current_address += read_count # Move to the next block
                # Potentially reset read_count if it was reduced due to errors
                read_count = MAX_READ_COUNT_COILS if fc in [FC_READ_COILS, FC_READ_DISCRETE_INPUTS] else MAX_READ_COUNT_REGISTERS


        logger.info(f"Unit {self.unit_id}: Finished adaptive scan for FC{fc}.")
        return results


# Example Usage (for testing this module)
async def main_test_scanner():
    # Setup basic logging for testing
    console = None
    try:
        from rich.console import Console
        from rich.logging import RichHandler
        console = Console()
        logging.basicConfig(level="DEBUG", format="%(message)s", datefmt="[%X]", handlers=[RichHandler(console=console, rich_tracebacks=True)])
    except ImportError:
        logging.basicConfig(level="DEBUG", format="%(asctime)s - %(levelname)s - %(message)s")

    # Requires a Modbus TCP server (e.g., diagslave -m tcp -p 502)
    test_host = "localhost"
    test_port = 502
    test_unit_id = 1 # Common default

    client = AsyncModbusTcpClient(test_host, port=test_port, timeout=2)
    if not await client.connect():
        logger.error(f"Failed to connect to {test_host}:{test_port} for scanner test.")
        return

    scanner = ModbusScanner(client, unit_id=test_unit_id)

    logger.info(f"--- Checking FC Support for Unit {test_unit_id} ---")
    fc_support = await scanner.check_function_code_support()
    for fc, supported in fc_support.items():
        logger.info(f"FC {fc}: {'Supported' if supported else 'Not Supported/Error'}")

    if fc_support.get(FC_READ_HOLDING_REGISTERS):
        logger.info(f"--- Reading Holding Registers (FC3) for Unit {test_unit_id} (example) ---")
        # Assuming diagslave default: registers 0-9 are 0, 10-19 are 100, etc.
        regs = await scanner.read_holding_registers(address=0, count=10)
        if regs:
            logger.info(f"Holding Registers 0-9: {regs}")
        else:
            logger.warning("Failed to read holding registers or empty response.")

        # Test adaptive scan (placeholder)
        logger.info(f"--- Adaptive Scan for Holding Registers (FC3) for Unit {test_unit_id} ---")
        # Diagslave default has registers up to 50000+ but let's test a smaller range
        # It usually has data at 0-9, 10-19, etc.
        # With default diagslave, addresses like 0-99 should be readable.
        # Addresses beyond what diagslave is configured for might give "Illegal Data Address".
        scan_results_fc3 = await scanner.discover_valid_ranges_and_dump(FC_READ_HOLDING_REGISTERS, max_addr=20) # Small range for test
        if console:
            from rich.pretty import pprint
            pprint(scan_results_fc3, expand_all=True)
        else:
            import json
            logger.info(json.dumps(scan_results_fc3, indent=2))


    if fc_support.get(FC_READ_COILS):
        logger.info(f"--- Reading Coils (FC1) for Unit {test_unit_id} (example) ---")
        # Diagslave default: coils 0-x exist
        coils = await scanner.read_coils(address=0, count=10)
        if coils:
            logger.info(f"Coils 0-9: {coils}")
        else:
            logger.warning("Failed to read coils or empty response.")

        logger.info(f"--- Adaptive Scan for Coils (FC1) for Unit {test_unit_id} ---")
        scan_results_fc1 = await scanner.discover_valid_ranges_and_dump(FC_READ_COILS, max_addr=20)
        if console:
            from rich.pretty import pprint
            pprint(scan_results_fc1, expand_all=True)
        else:
            import json
            logger.info(json.dumps(scan_results_fc1, indent=2))


    await client.close()

# The main_test_scanner() function and its call are removed to prevent syntax errors
# during import, as this file is not intended to be run directly anymore.
# For module-specific tests, use the unittest framework in the tests/ directory.
