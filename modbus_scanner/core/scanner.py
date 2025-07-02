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
        if not self.client: # Simpler check: ensure a client object is passed.
            # The responsibility for the client being connected lies with the code that calls the scanner.
            raise ValueError("Modbus client has not been provided to ModbusScanner.")
        logger.debug(f"ModbusScanner initialized for Unit ID {self.unit_id}")

    async def _execute_read_request(self, fc: int, address: int, count: int) -> Optional[Any]:
        """
        Helper to execute a read request with timeout and error handling.
        """
        response = None
        try:
            logger.debug(f"Unit {self.unit_id}: Reading FC{fc} @ Address {address}, Count {count}")
            # address is positional, count and slave are keywords
            if fc == FC_READ_COILS:
                response = await self.client.read_coils(address, count=count, slave=self.unit_id)
            elif fc == FC_READ_DISCRETE_INPUTS:
                response = await self.client.read_discrete_inputs(address, count=count, slave=self.unit_id)
            elif fc == FC_READ_HOLDING_REGISTERS:
                response = await self.client.read_holding_registers(address, count=count, slave=self.unit_id)
            elif fc == FC_READ_INPUT_REGISTERS:
                response = await self.client.read_input_registers(address, count=count, slave=self.unit_id)
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
        :param max_addr: Maximum address to check (inclusive).
        :return: Dictionary with results, including 'fc', 'unit_id', 'status', 'valid_ranges', and 'errors'.
                 'valid_ranges' is a list of dicts: {'start_address': X, 'count': Y, 'values': [...]}.
                 'errors' is a list of dicts: {'address': X, 'type': 'error_type', 'message': '...'}.
        """
        logger.info(f"Unit {self.unit_id}: Starting data discovery for FC{fc} up to address {max_addr}")
        # Define the structure for results
        scan_result = {
            "fc": fc,
            "unit_id": self.unit_id,
            "status": "pending", # pending, success, partial_success, failed
            "valid_ranges": [], # List of {'start_address': X, 'values': [...]}
            "errors": [] # List of {'address': X, 'type': 'error_type', 'message': '...'}
        }

        current_address = 0
        is_coil_type = fc in [FC_READ_COILS, FC_READ_DISCRETE_INPUTS]
        max_initial_read_count = MAX_READ_COUNT_COILS if is_coil_type else MAX_READ_COUNT_REGISTERS

        successful_reads = 0
        errors_encountered = 0

        while current_address <= max_addr:
            current_read_count = max_initial_read_count

            # This inner loop is for adaptive retry with smaller counts
            while True:
                count_to_attempt = min(current_read_count, max_addr - current_address + 1)
                if count_to_attempt <= 0:
                    break # Break inner retry loop, will also break outer due to current_address condition

                response = await self._execute_read_request(fc, current_address, count_to_attempt)

                if response is None: # Timeout or communication error
                    msg = f"No response/timeout for FC{fc} at {current_address}, count {count_to_attempt}"
                    logger.warning(f"Unit {self.unit_id}: {msg}")
                    scan_result["errors"].append({"address": current_address, "type": "timeout_or_comms_error", "message": msg, "count_attempted": count_to_attempt})
                    errors_encountered +=1
                    current_address += count_to_attempt # Skip this block
                    break # Break inner retry loop

                if response.isError():
                    if isinstance(response, ExceptionResponse):
                        exc_code = response.exception_code
                        error_msg = f"Modbus Exception FC{fc} @ {current_address}, Code: {exc_code}"
                        scan_result["errors"].append({"address": current_address, "type": "modbus_exception", "code": exc_code, "message": error_msg, "count_attempted": count_to_attempt})
                        errors_encountered +=1

                        if exc_code == 2: # Illegal Data Address
                            if current_read_count > 1:
                                current_read_count = max(1, current_read_count // 2) # Halve read count and retry
                                logger.debug(f"Unit {self.unit_id}: FC{fc} - Illegal Data Address at {current_address}. Reducing read count to {current_read_count} and retrying.")
                                continue # Retry same address with smaller count (inner loop)
                            else: # Already trying with count 1
                                current_address += 1 # Move to next single address
                                break # Break inner retry loop
                        elif exc_code == 1: # Illegal Function
                            logger.warning(f"Unit {self.unit_id}: {error_msg}. Stopping scan for this FC.")
                            scan_result["status"] = "failed_illegal_function"
                            return scan_result # Abort this FC scan entirely
                        else: # Other Modbus errors
                            logger.warning(f"Unit {self.unit_id}: {error_msg}. Skipping block of size {count_to_attempt}.")
                            current_address += count_to_attempt
                            break # Break inner retry loop
                    else: # Generic Pymodbus error object
                        error_msg = f"Generic Modbus Error for FC{fc} @ {current_address}: {str(response)}"
                        logger.warning(f"Unit {self.unit_id}: {error_msg}")
                        scan_result["errors"].append({"address": current_address, "type": "generic_modbus_error", "message": error_msg, "count_attempted": count_to_attempt})
                        errors_encountered +=1
                        current_address += count_to_attempt # Skip block
                        break # Break inner retry loop
                else: # Successful read
                    data_values = response.bits if is_coil_type else response.registers
                    # response.bits might be longer than count_to_attempt due to byte packing, slice it.
                    # response.registers should match count_to_attempt.
                    actual_items_read = min(len(data_values), count_to_attempt)

                    if actual_items_read > 0:
                        valid_data_segment = data_values[:actual_items_read]
                        scan_result["valid_ranges"].append({
                            "start_address": current_address,
                            "count": actual_items_read,
                            "values": valid_data_segment
                        })
                        successful_reads += 1
                        logger.info(f"Unit {self.unit_id}: FC{fc} @ {current_address}-{current_address + actual_items_read - 1} -> Read {actual_items_read} items.")
                    else: # Read 0 items successfully (e.g. device returned empty list for valid request)
                        logger.info(f"Unit {self.unit_id}: FC{fc} @ {current_address} - Read successful but 0 items returned by device for count {count_to_attempt}.")
                        # Consider if this should be an error or a specific status
                        scan_result["errors"].append({
                            "address": current_address,
                            "type": "success_read_zero_items",
                            "message": f"Successfully read 0 items for FC{fc} at {current_address} count {count_to_attempt}",
                            "count_attempted": count_to_attempt
                        })


                    current_address += actual_items_read
                    break # Break inner retry loop (successfully processed this block)

            if count_to_attempt <= 0: # Condition to exit outer while loop if max_addr is reached
                break

        if successful_reads > 0 and errors_encountered > 0:
            scan_result["status"] = "partial_success"
        elif successful_reads > 0:
            scan_result["status"] = "success"
        elif errors_encountered > 0:
            scan_result["status"] = "failed"
        else: # No reads, no errors (e.g., max_addr was 0 or negative)
            scan_result["status"] = "no_operation"


        logger.info(f"Unit {self.unit_id}: Finished data discovery for FC{fc}. Status: {scan_result['status']}. Ranges found: {len(scan_result['valid_ranges'])}. Errors: {len(scan_result['errors'])}.")
        return scan_result

# The main_test_scanner() function and its call are removed to prevent syntax errors
# during import, as this file is not intended to be run directly anymore.
# For module-specific tests, use the unittest framework in the tests/ directory.
# The main_test_scanner() function and its call are removed to prevent syntax errors
# during import, as this file is not intended to be run directly anymore.
# For module-specific tests, use the unittest framework in the tests/ directory.
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
