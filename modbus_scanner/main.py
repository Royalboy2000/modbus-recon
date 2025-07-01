# main.py
"""
Modbus TCP Reconnaissance and Enumeration Script

This script provides functionalities to discover, fingerprint, and enumerate
Modbus TCP devices on a network.
"""

import argparse
import logging
import asyncio
import sys # For platform check if using WindowsSelectorEventLoopPolicy

from rich.console import Console
from rich.logging import RichHandler

from modbus_scanner.utils import config_loader, network_utils, param_parser
# from modbus_scanner.core import scanner, connector # Will be used in next steps

# Initialize Rich Console for beautiful output
# This will be global for now, or passed around.
console = Console()

# Setup basic logging using RichHandler
# The actual logger configuration (levels based on verbosity) will happen in main()
# after args are parsed, especially for the `no_color` option.
# Set a base level here; it will be adjusted.
# Use a specific logger for the application to avoid interfering with other libraries' logging.
logger = logging.getLogger("modbus_scanner_app")
# Configure the RichHandler for our specific logger
rich_handler = RichHandler(console=console, rich_tracebacks=True, show_path=False)
logger.addHandler(rich_handler)
logger.setLevel(logging.INFO) # Default level, will be overridden by verbosity args
# Prevent passing messages to the root logger if it has its own handlers
logger.propagate = False


# --- Main Program Logic (will become async) ---
async def main_program_logic(config: dict):
    """
    Contains the core logic for scanning after configuration is processed.
    """
    global console # If console is modified (e.g. no_color)

    logger.info(f"Effective configuration (first few items): { {k: config[k] for k in list(config)[:5]} }...") # Log a snippet
    logger.debug(f"Full effective configuration: {config}")


    # --- Parse Targets and Unit IDs ---
    try:
        ip_targets = network_utils.parse_ip_targets(config.get("target", ""))
        if not ip_targets:
            logger.error("[bold red]No valid IP targets specified. Exiting.[/bold red]")
            return
    except Exception as e:
        logger.error(f"[bold red]Error parsing IP targets: {e}. Exiting.[/bold red]")
        return

    try:
        unit_ids_to_scan = param_parser.parse_unit_ids(
            str(config.get("unit_ids", "")), # Ensure it's a string for parser
            min_val=0,
            max_val=255
        )
        if not unit_ids_to_scan:
            # Use default if parsing result is empty and original config string was also empty or None
            # This handles the case where neither CLI nor config file specifies unit_ids
            if not config.get("unit_ids"): # Check if it was empty in the first place
                 default_unit_ids_str = config_loader.DEFAULT_CONFIG_VALUES.get("unit_ids", "1-247")
                 logger.info(f"No Unit IDs provided, using default: {default_unit_ids_str}")
                 unit_ids_to_scan = param_parser.parse_unit_ids(default_unit_ids_str, min_val=0, max_val=255)

            if not unit_ids_to_scan: # If still no units after trying default
                logger.error("[bold red]No valid Unit IDs to scan even after defaults. Exiting.[/bold red]")
                return

    except Exception as e:
        logger.error(f"[bold red]Error parsing Unit IDs: {e}. Exiting.[/bold red]")
        return

    logger.info(f"Target IPs to scan ({len(ip_targets)}): {ip_targets[:5]}..." if len(ip_targets) > 5 else ip_targets)
    logger.info(f"Unit IDs to scan ({len(unit_ids_to_scan)}): {unit_ids_to_scan[:10]}..." if len(unit_ids_to_scan) > 10 else unit_ids_to_scan)
    logger.info(f"Port: {config.get('port')}, Timeout: {config.get('timeout')}s")
    if config.get('fast_scan'): # fast_scan can be True, False, or None from argparse.BooleanOptionalAction
        logger.info("[bold yellow]Fast scan enabled.[/bold yellow]")
    elif config.get('fast_scan') is False: # Explicitly --no-fast-scan
        logger.info("Fast scan disabled by user.")


    console.rule("[bold blue]Initiating Scan (Conceptual - Core Logic Pending)[/bold blue]")
    all_results = []

    # --- Actual Scanning Logic ---
    from modbus_scanner.core.connector import ModbusConnector
    from modbus_scanner.core.scanner import ModbusScanner

    # Progress bar for overall IP scanning
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False # Keep progress displayed after completion
    ) as progress:
        ip_scan_task = progress.add_task("[cyan]Scanning IPs...", total=len(ip_targets))

        for ip_index, ip in enumerate(ip_targets):
            progress.update(ip_scan_task, description=f"[cyan]Scanning IP: {ip} ({ip_index+1}/{len(ip_targets)})")

            # Per-IP results or status
            ip_scan_data = {"ip": ip, "port": config.get('port'), "units": []}

            connector = ModbusConnector(
                host=ip,
                port=int(config.get('port', 502)),
                timeout=float(config.get('timeout', 1.0))
            )

            if not await connector.connect():
                message = f"Failed to connect to {ip}:{config.get('port')}"
                logger.warning(message)
                console.print(f"[yellow]  - {message}[/yellow]")
                ip_scan_data["status"] = "connection_failed"
                all_results.append(ip_scan_data)
                progress.advance(ip_scan_task)
                continue

            logger.info(f"Successfully connected to {ip}:{config.get('port')}")
            ip_scan_data["status"] = "connected"

            unit_scan_task = progress.add_task(f"  Units for {ip}", total=len(unit_ids_to_scan), indent=2)

            for unit_id in unit_ids_to_scan:
                progress.update(unit_scan_task, description=f"  Scanning Unit ID: {unit_id} for {ip}")
                unit_data = {"unit_id": unit_id}

                console.print(f"  [steel_blue]-> Probing Unit ID: {unit_id} on {ip}[/steel_blue]")
                try:
                    # Ensure client is valid before creating ModbusScanner
                    client = connector.get_client()
                    if not client: # Removed 'is_active' check
                        logger.error(f"Client for {ip} is not available before scanning unit {unit_id}. Should not happen if connect succeeded and connector.get_client() returned a client.")
                        unit_data["error"] = "Client not available from connector"
                        ip_scan_data["units"].append(unit_data)
                        progress.advance(unit_scan_task)
                        continue # to next unit id, or perhaps break from units for this IP

                    modbus_scanner = ModbusScanner(client=client, unit_id=unit_id)

                    # Check Function Code Support
                    fc_support = await modbus_scanner.check_function_code_support()
                    unit_data["fc_support"] = fc_support
                    console.print(f"    [green]FC Support:[/green] {fc_support}")

                    # Placeholder for discover_valid_ranges_and_dump if fc is supported
                    # This will be expanded in the next plan step (Enhance ModbusScanner.py)
                    # For now, just log what would be done
                    supported_fcs_to_dump = [fc for fc, supported in fc_support.items() if supported]
                    if supported_fcs_to_dump:
                        logger.debug(f"Unit {unit_id} on {ip}: Would attempt to dump data for FCs: {supported_fcs_to_dump}")
                        # Example call structure (to be implemented fully later):
                        # for fc_to_scan in supported_fcs_to_dump:
                        #     dump_results = await modbus_scanner.discover_valid_ranges_and_dump(fc_to_scan)
                        #     unit_data[f"fc{fc_to_scan}_dump"] = dump_results
                        #     console.print(f"      Dump for FC{fc_to_scan}: {dump_results.get('data')[:1]}..." if dump_results.get('data') else "No data")
                    else:
                        logger.info(f"Unit {unit_id} on {ip}: No function codes reported as supported for data dumping.")

                except Exception as e_scan:
                    error_msg = f"Error scanning unit {unit_id} on {ip}: {e_scan}"
                    logger.error(error_msg, exc_info=True)
                    console.print(f"    [red]Error:[/red] {error_msg}")
                    unit_data["error"] = str(e_scan)

                ip_scan_data["units"].append(unit_data)
                progress.advance(unit_scan_task)

            progress.remove_task(unit_scan_task) # Clean up unit progress bar for this IP
            await connector.disconnect()
            all_results.append(ip_scan_data)
            progress.advance(ip_scan_task)

    console.rule("[bold red]Scan Complete[/bold red]")
    logger.info("Modbus Scan Main Loop Finished.")
    if all_results:
        console.print("\n[bold green]Collected Results (Summary - Placeholder):[/bold green]")
        from rich.pretty import pprint
        pprint(all_results)


def main():
    """
    Main function to parse arguments, set up logging, load configuration,
    and then call the core asynchronous scanning logic.
    """
    global console
    global rich_handler # To update its console if --no-color

    parser = argparse.ArgumentParser(
        description="Modbus TCP Reconnaissance and Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target and Connection Arguments
    parser.add_argument(
        "target",
        help="Target IP address, IP range (e.g., \"192.168.1.1-100\"), CIDR (e.g., \"192.168.1.0/24\"), or comma-separated list."
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Modbus TCP port. Overrides config. (Default: from config or 502)"
    )
    parser.add_argument(
        "-u", "--unit-ids",
        type=str,
        default=None,
        help="Unit IDs (e.g., \"1,2,5-10\"). Overrides config. (Default: from config or 1-247)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Connection/request timeout (seconds). Overrides config. (Default: from config or 1.0)"
    )

    # Scan Behavior Arguments
    parser.add_argument(
        "--fast-scan",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Perform a faster, less comprehensive scan. Use --no-fast-scan to disable if enabled in config."
    )

    # Configuration File Argument
    parser.add_argument(
        "-c", "--config",
        default="config/config.yml",
        help="Path to YAML configuration file (default: %(default)s)."
    )

    # Output Arguments
    parser.add_argument(
        "-o", "--output-prefix",
        type=str, # Explicitly type as string
        default=None,
        help="Prefix for output files (e.g., 'scan_results'). Overrides config. (Default: from config or 'scan_results')"
    )

    # General Application Arguments
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (-v INFO, -vv DEBUG, -vvv Pymodbus DEBUG)."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0" # Placeholder version
    )

    args = parser.parse_args()

    # --- Configure Console and Logging based on args ---
    if args.no_color:
        console = Console(no_color=True)
        # Update RichHandler with the new console
        # Remove old handler, add new one to the specific logger
        logger.removeHandler(rich_handler)
        rich_handler = RichHandler(console=console, rich_tracebacks=True, show_path=False)
        logger.addHandler(rich_handler)


    # Set logging levels based on verbosity
    app_logger_instance = logging.getLogger("modbus_scanner_app") # Get the instance of our app's logger
    pymodbus_logger = logging.getLogger("pymodbus")

    if args.verbose == 0:
        app_logger_instance.setLevel(logging.INFO)
        pymodbus_logger.setLevel(logging.ERROR)
    elif args.verbose == 1:
        app_logger_instance.setLevel(logging.INFO) # App INFO messages are fine
        pymodbus_logger.setLevel(logging.WARNING) # Less noise from pymodbus
        app_logger_instance.info("Verbosity -v: App INFO, Pymodbus WARNING")
    elif args.verbose == 2:
        app_logger_instance.setLevel(logging.DEBUG)
        pymodbus_logger.setLevel(logging.INFO)
        app_logger_instance.debug("Verbosity -vv: App DEBUG, Pymodbus INFO")
    else: # -vvv or more
        app_logger_instance.setLevel(logging.DEBUG)
        pymodbus_logger.setLevel(logging.DEBUG)
        app_logger_instance.debug("Verbosity -vvv: App DEBUG, Pymodbus DEBUG")

    # Initial log message
    logger.info(f"[bold green]Modbus Scanner starting...[/bold green]")
    logger.debug(f"Command line arguments: {vars(args)}")


    # --- Load and Merge Configuration ---
    file_cfg = config_loader.load_config_file(args.config)
    config = config_loader.merge_configs(args, file_cfg) # merge_configs uses DEFAULT_CONFIG_VALUES as base

    # --- Run the main asynchronous program logic ---
    try:
        if sys.platform == "win32" and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        asyncio.run(main_program_logic(config))

    except KeyboardInterrupt:
        console.print("\n[bold orange_red1]Scan interrupted by user. Exiting...[/bold orange_red1]")
    except Exception as e:
        logger.error(f"[bold red]An unexpected critical error occurred in main: {e}[/bold red]", exc_info=True)
        # console.print_exception(show_locals=True) # Rich handler should do this if logger.error has exc_info=True
    finally:
        logger.info("[bold green]Modbus Scanner finished.[/bold green]")


if __name__ == "__main__":
    main()
