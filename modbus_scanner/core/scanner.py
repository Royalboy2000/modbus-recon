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

        # Basic placeholder logic: Try to read a small number of registers/coils at address 0
        # This will be significantly expanded with adaptive logic in the next step.
        test_address = 0
        test_count = 0
        is_coil_type = fc in [FC_READ_COILS, FC_READ_DISCRETE_INPUTS]

        if is_coil_type:
            test_count = min(16, MAX_READ_COUNT_COILS) # Read a few coils
        else:
            test_count = min(5, MAX_READ_COUNT_REGISTERS) # Read a few registers

        if test_address + test_count -1 > max_addr : # Ensure test read is within max_addr
             if max_addr < test_address:
                 logger.info(f"Unit {self.unit_id}: FC{fc} - Max address {max_addr} is less than test start address {test_address}. Skipping dump.")
                 scan_result["status"] = "skipped_max_addr"
                 return scan_result
             test_count = max_addr - test_address + 1


        if test_count <= 0:
            logger.info(f"Unit {self.unit_id}: FC{fc} - No addresses to scan up to max_addr {max_addr} from start {test_address}. Skipping dump.")
            scan_result["status"] = "skipped_no_range"
            return scan_result

        response = await self._execute_read_request(fc, test_address, test_count)

        if response is None:
            error_detail = {"address": test_address, "type": "timeout_or_comms_error", "message": f"No response for FC{fc} at {test_address} count {test_count}"}
            scan_result["errors"].append(error_detail)
            scan_result["status"] = "failed"
            logger.warning(f"Unit {self.unit_id}: FC{fc} @ {test_address} - {error_detail['message']}")
        elif response.isError():
            error_type = "modbus_exception"
            error_code = getattr(response, 'exception_code', 'N/A')
            if isinstance(response, ExceptionResponse):
                 error_message = f"Modbus Exception Code: {response.exception_code}"
            else:
                 error_message = str(response)

            error_detail = {"address": test_address, "type": error_type, "code": error_code, "message": error_message}
            scan_result["errors"].append(error_detail)
            scan_result["status"] = "failed_exception"
            logger.warning(f"Unit {self.unit_id}: FC{fc} @ {test_address} - {error_message} (Code: {error_code})")
        else:
            # Successful read (for this basic test)
            data_values = []
            if is_coil_type:
                data_values = response.bits[:test_count]
            else: # Register type
                data_values = response.registers[:test_count]

            if data_values:
                scan_result["valid_ranges"].append({
                    "start_address": test_address,
                    "count": len(data_values), # Actual number of items read and returned
                    "values": data_values
                })
                scan_result["status"] = "success" # Or "partial_success" if adaptive scanning was incomplete
                logger.info(f"Unit {self.unit_id}: FC{fc} @ {test_address} - Successfully read {len(data_values)} items.")
            else:
                scan_result["status"] = "success_no_data" # Valid response but no data (e.g. read 0 items successfully)
                logger.info(f"Unit {self.unit_id}: FC{fc} @ {test_address} - Read successful but no data returned in response list.")

        logger.info(f"Unit {self.unit_id}: Finished data discovery for FC{fc}. Status: {scan_result['status']}")
        return scan_result


# Example Usage (for testing this module)
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
