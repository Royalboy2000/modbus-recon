# modbus_scanner/utils/param_parser.py
"""
Utility functions for parsing parameters like Unit IDs.
"""
import logging
from typing import List, Set

logger = logging.getLogger("rich")

def parse_unit_ids(unit_id_str: str, min_val: int = 0, max_val: int = 255) -> List[int]:
    """
    Parses a string of Unit IDs into a sorted list of unique integers.
    The string can contain comma-separated numbers and ranges (e.g., "1,2,5-10,20").
    Unit IDs are typically 1-247 for Modbus, 0 for broadcast (not usually targeted for reads),
    and 248-255 are reserved. pymodbus typically uses 0-255.
    We will allow 0-255 by default but specific Modbus applications might constrain this.

    :param unit_id_str: The string to parse.
    :param min_val: Minimum allowed unit ID.
    :param max_val: Maximum allowed unit ID.
    :return: A sorted list of unique integer unit IDs.
    """
    if not unit_id_str:
        return []

    unit_ids: Set[int] = set()
    parts = unit_id_str.split(',')

    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part: # Range
                start_str, end_str = part.split('-', 1)
                start = int(start_str)
                end = int(end_str)
                if start > end:
                    logger.warning(f"Invalid unit ID range '{part}': start > end. Skipping.")
                    continue
                for i in range(start, end + 1):
                    if min_val <= i <= max_val:
                        unit_ids.add(i)
                    else:
                        logger.warning(f"Unit ID {i} from range '{part}' is outside allowed range ({min_val}-{max_val}). Skipping.")
            else: # Single number
                unit_id = int(part)
                if min_val <= unit_id <= max_val:
                    unit_ids.add(unit_id)
                else:
                    logger.warning(f"Unit ID {unit_id} from '{part}' is outside allowed range ({min_val}-{max_val}). Skipping.")
        except ValueError:
            logger.warning(f"Invalid unit ID format in '{part}'. Must be integer or range (e.g., 5-10). Skipping.")
            continue
        except Exception as e:
            logger.error(f"Unexpected error parsing unit ID part '{part}': {e}. Skipping.")
            continue

    return sorted(list(unit_ids))
