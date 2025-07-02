# modbus_scanner/output/writers.py
"""
Functions for writing scan results to various output formats (JSON, CSV, etc.).
"""
import json
import csv
import logging
from typing import List, Dict, Any

logger = logging.getLogger("modbus_scanner_app")

def write_json_output(results: List[Dict[str, Any]], filename: str) -> bool:
    """
    Writes the scan results to a JSON file.

    :param results: A list of dictionaries containing the scan results.
    :param filename: The name of the JSON file to write to.
    :return: True if writing was successful, False otherwise.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully wrote JSON output to [green]{filename}[/green]")
        return True
    except IOError as e:
        logger.error(f"[bold red]IOError writing JSON to {filename}: {e}[/bold red]")
    except Exception as e:
        logger.error(f"[bold red]Unexpected error writing JSON to {filename}: {e}[/bold red]", exc_info=True)
    return False

def write_summary_csv_output(results: List[Dict[str, Any]], filename: str) -> bool:
    """
    Writes a summary of scan results to a CSV file.
    Each row will represent a unit scanned for a specific IP.

    :param results: A list of dictionaries containing the scan results.
    :param filename: The name of the CSV file to write to.
    :return: True if writing was successful, False otherwise.
    """
    fieldnames = [
        "IP Address", "Port", "Unit ID", "Scan Status",
        "FC1 Read Coils", "FC2 Read Discrete Inputs",
        "FC3 Read Holding Registers", "FC4 Read Input Registers",
        "Data Dump Summary", "Error Info"
    ]

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip_result in results:
                ip_address = ip_result.get("ip", "N/A")
                port = ip_result.get("port", "N/A")
                ip_status = ip_result.get("status", "N/A")

                if not ip_result.get("units") and ip_status == "connection_failed":
                    writer.writerow({
                        "IP Address": ip_address,
                        "Port": port,
                        "Unit ID": "N/A",
                        "Scan Status": "Connection Failed",
                        "FC1 Read Coils": "N/A",
                        "FC2 Read Discrete Inputs": "N/A",
                        "FC3 Read Holding Registers": "N/A",
                        "FC4 Read Input Registers": "N/A",
                        "Data Dump Summary": "N/A",
                        "Error Info": "Connection to host failed"
                    })
                    continue

                for unit_scan_data in ip_result.get("units", []):
                    unit_id = unit_scan_data.get("unit_id", "N/A")
                    fc_support = unit_scan_data.get("fc_support", {})
                    error_info = unit_scan_data.get("error", "")
                    scan_status = "Error" if error_info else unit_scan_data.get("fc_scan_status", "Unknown")

                    dump_summary_parts = []
                    data_dumps = unit_scan_data.get("data_dumps", {})
                    if isinstance(data_dumps, dict):
                        for fc_key, dump_res in data_dumps.items():
                            if dump_res.get("status") == "success" and dump_res.get("valid_ranges"):
                                num_items = sum(len(r.get("values",[])) for r in dump_res["valid_ranges"])
                                dump_summary_parts.append(f"{fc_key}: {num_items} items")
                            elif dump_res.get("status") == "success_no_data":
                                 dump_summary_parts.append(f"{fc_key}: No Data")
                            elif dump_res.get("status") and dump_res["status"] not in ["pending", "success"]:
                                dump_summary_parts.append(f"{fc_key}: {dump_res['status']}")
                    elif isinstance(data_dumps, str): # e.g. "skipped_no_fc_support"
                        dump_summary_parts.append(data_dumps)


                    row = {
                        "IP Address": ip_address,
                        "Port": port,
                        "Unit ID": unit_id,
                        "Scan Status": scan_status,
                        "FC1 Read Coils": str(fc_support.get(1, "N/A")),
                        "FC2 Read Discrete Inputs": str(fc_support.get(2, "N/A")),
                        "FC3 Read Holding Registers": str(fc_support.get(3, "N/A")),
                        "FC4 Read Input Registers": str(fc_support.get(4, "N/A")),
                        "Data Dump Summary": "; ".join(dump_summary_parts) if dump_summary_parts else "No dumps attempted or N/A",
                        "Error Info": str(error_info)[:255] # Limit error string length for CSV
                    }
                    writer.writerow(row)

        logger.info(f"Successfully wrote CSV summary to [green]{filename}[/green]")
        return True
    except IOError as e:
        logger.error(f"[bold red]IOError writing CSV to {filename}: {e}[/bold red]")
    except Exception as e:
        logger.error(f"[bold red]Unexpected error writing CSV to {filename}: {e}[/bold red]", exc_info=True)
    return False

if __name__ == '__main__':
    # Example Usage for testing writers.py independently
    # This would typically be run from the project root: python -m modbus_scanner.output.writers

    logger.parent.setLevel(logging.DEBUG) # Ensure parent logger (root or specific) is also at DEBUG
    console = Console()
    logger.addHandler(RichHandler(console=console, rich_tracebacks=True))


    mock_results_complex = [
        {
            "ip": "192.168.1.10",
            "port": 502,
            "status": "connected",
            "units": [
                {
                    "unit_id": 1,
                    "fc_support": {1: True, 2: False, 3: True, 4: False},
                    "fc_scan_status": "success",
                    "data_dumps": {
                        "fc1": {"status": "success", "valid_ranges": [{"start_address": 0, "count": 8, "values": [True]*8}]},
                        "fc3": {"status": "success", "valid_ranges": [{"start_address": 0, "count": 2, "values": [123, 456]}]}
                    }
                },
                {
                    "unit_id": 2,
                    "fc_support": {1: False, 2: False, 3: False, 4: False},
                    "fc_scan_status": "success", # FCs checked, none supported
                    "data_dumps": "skipped_no_fc_support",
                    "error": "Some minor note here"
                }
            ]
        },
        {
            "ip": "192.168.1.11",
            "port": 502,
            "status": "connection_failed",
            "units": [] # No unit data because connection failed
        },
         {
            "ip": "192.168.1.12",
            "port": 502,
            "status": "connected",
            "units": [
                {
                    "unit_id": 1,
                    "fc_support": {1: True, 2: True, 3: True, 4: True},
                    "fc_scan_status": "success",
                    "data_dumps": {
                        "fc1": {"status": "success_no_data", "valid_ranges": []},
                        "fc3": {"status": "failed_exception", "errors": [{"message": "Illegal Address"}]}
                    }
                }
            ]
        }
    ]

    json_filename = "test_scan_results.json"
    csv_filename = "test_scan_summary.csv"

    logger.info(f"Attempting to write JSON to: {json_filename}")
    if write_json_output(mock_results_complex, json_filename):
        with open(json_filename, 'r') as f:
            logger.debug(f"JSON content:\n{f.read()[:500]}...") # Print snippet

    logger.info(f"\nAttempting to write CSV to: {csv_filename}")
    if write_summary_csv_output(mock_results_complex, csv_filename):
        with open(csv_filename, 'r') as f:
            logger.debug(f"CSV content:\n{f.read()[:500]}...")

    logger.info("\nWriter tests finished. Check created files.")

    # Clean up test files
    # import os
    # if os.path.exists(json_filename): os.remove(json_filename)
    # if os.path.exists(csv_filename): os.remove(csv_filename)
