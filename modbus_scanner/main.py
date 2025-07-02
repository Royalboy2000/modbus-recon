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
    from rich.live import Live
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn, SpinnerColumn

    overall_progress_columns = [
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
    ]

    with Progress(*overall_progress_columns, console=console, transient=False) as overall_progress:
        ip_scan_task = overall_progress.add_task("[cyan]Scanning IPs...", total=len(ip_targets))

        for ip_index, ip in enumerate(ip_targets):
            overall_progress.update(ip_scan_task, description=f"[cyan]Scanning IP: {ip} ({ip_index+1}/{len(ip_targets)})")

            ip_scan_data = {"ip": ip, "port": config.get('port'), "units": []}

            connector = ModbusConnector(
                host=ip,
                port=int(config.get('port', 502)),
                timeout=float(config.get('timeout', 1.0))
            )

            if not await connector.connect():
                message = f"Failed to connect to {ip}:{config.get('port')}"
                logger.warning(message)
                # No need to console.print here if Live is active, but Live is per-IP.
                # So, if connection fails before Live starts for units, print is okay.
                overall_progress.console.print(f"[yellow]  - {message}[/yellow]")
                ip_scan_data["status"] = "connection_failed"
                all_results.append(ip_scan_data)
                overall_progress.advance(ip_scan_task)
                continue

            logger.info(f"Successfully connected to {ip}:{config.get('port')}")
            ip_scan_data["status"] = "connected"

            # Data structure to hold unit scan information for the live table
            # Dict: {unit_id: [status_str, fc_support_str, details_str]}
            live_unit_display_data = {}

            # Define the table for live updates for the current IP
            unit_table = Table(title=f"Units for {ip} - Connecting...")
            unit_table.add_column("Unit ID", style="dim", width=10)
            unit_table.add_column("Status", width=25)
            unit_table.add_column("FC Support", width=30)
            unit_table.add_column("Details", no_wrap=False) # Allow wrapping for longer error messages

            with Live(unit_table, console=console, refresh_per_second=5, transient=True) as live:
                for unit_idx, unit_id in enumerate(unit_ids_to_scan):
                    # Initial status for the unit
                    live_unit_display_data[unit_id] = [
                        f"[cyan]Probing FCs ({unit_idx+1}/{len(unit_ids_to_scan)})...[/cyan]", "", ""
                    ]

                    # Rebuild and update table
                    current_title = f"Units for {ip} - Scanning Unit {unit_id} ({unit_idx+1}/{len(unit_ids_to_scan)})"
                    temp_table = Table(title=current_title)
                    temp_table.add_column("Unit ID", style="dim", width=10)
                    temp_table.add_column("Status", width=25)
                    temp_table.add_column("FC Support", width=30)
                    temp_table.add_column("Details", no_wrap=False)
                    for uid_disp in sorted(live_unit_display_data.keys()):
                        status, fc_str, details_str = live_unit_display_data[uid_disp]
                        temp_table.add_row(str(uid_disp), status, fc_str, details_str)
                    live.update(temp_table)

                    unit_data_for_results = {"unit_id": unit_id}
                    fc_support_str = "[red]Error[/red]" # Default in case of early exit
                    details_str = ""

                    try:
                        client = connector.get_client()
                        if not client:
                            error_msg = "Client not available from connector."
                            logger.error(f"Unit {unit_id} on {ip}: {error_msg}")
                            live_unit_display_data[unit_id] = ["[red]Client Error[/red]", "", error_msg]
                            unit_data_for_results["error"] = error_msg
                            ip_scan_data["units"].append(unit_data_for_results)
                            # No need to advance overall_progress unit_scan_task here, it's removed
                            continue

                        modbus_scanner = ModbusScanner(client=client, unit_id=unit_id)

                        fc_support = await modbus_scanner.check_function_code_support()
                        unit_data_for_results["fc_support"] = fc_support

                        supported_fcs = [fc for fc, supported in fc_support.items() if supported]
                        if not supported_fcs:
                            fc_support_str = "[yellow]None[/yellow]"
                        else:
                            fc_support_str = ", ".join([f"[green]FC{fc}[/green]" for fc in supported_fcs])

                        live_unit_display_data[unit_id] = ["[green]Checked[/green]", fc_support_str, ""]
                        unit_data_for_results["fc_scan_status"] = "success"

                        if supported_fcs:
                            unit_data_for_results["data_dumps"] = {}
                            for fc_to_dump in supported_fcs:
                                live_unit_display_data[unit_id][0] = f"[yellow]Dumping FC{fc_to_dump}...[/yellow]"
                                # Rebuild and update table for dumping status
                                temp_table_dump_status = Table(title=current_title)
                                temp_table_dump_status.add_column("Unit ID", style="dim", width=10)
                                temp_table_dump_status.add_column("Status", width=25)
                                temp_table_dump_status.add_column("FC Support", width=30)
                                temp_table_dump_status.add_column("Details", no_wrap=False)
                                for uid_disp_inner in sorted(live_unit_display_data.keys()):
                                    status_i, fc_str_i, details_str_i = live_unit_display_data[uid_disp_inner]
                                    temp_table_dump_status.add_row(str(uid_disp_inner), status_i, fc_str_i, details_str_i)
                                live.update(temp_table_dump_status)

                                dump_result = await modbus_scanner.discover_valid_ranges_and_dump(
                                    fc=fc_to_dump,
                                    max_addr=config.get('max_coil_address', 9999) if fc_to_dump in [1,2] else config.get('max_register_address', 9999)
                                )
                                unit_data_for_results["data_dumps"][f"fc{fc_to_dump}"] = dump_result

                                if dump_result["status"] == "success" and dump_result["valid_ranges"]:
                                    num_items = sum(len(r.get("values", [])) for r in dump_result["valid_ranges"])
                                    details_str += f"FC{fc_to_dump}: Read {num_items} items. "
                                    live_unit_display_data[unit_id][0] = "[green]Dumped[/green]"
                                elif dump_result["status"] == "success_no_data":
                                    details_str += f"FC{fc_to_dump}: No data. "
                                    live_unit_display_data[unit_id][0] = "[green]Dumped (No Data)[/green]"
                                else: # errors or other statuses
                                    details_str += f"FC{fc_to_dump}: {dump_result['status']}. "
                                    live_unit_display_data[unit_id][0] = "[yellow]Dump Issues[/yellow]"
                                live_unit_display_data[unit_id][2] = details_str.strip()
                        else:
                            logger.info(f"Unit {unit_id} on {ip}: No function codes reported as supported for data dumping.")
                            live_unit_display_data[unit_id][2] = "No FCs to dump"
                            unit_data_for_results["data_dumps"] = "skipped_no_fc_support"

                    except Exception as e_scan:
                        error_msg = f"Scan error: {type(e_scan).__name__}"
                        logger.error(f"Unit {unit_id} on {ip}: {error_msg} - {str(e_scan)[:100]}...", exc_info=True)
                        live_unit_display_data[unit_id] = ["[red]Error[/red]", fc_support_str, f"[dim]{str(e_scan)[:100]}[/dim]"]
                        unit_data_for_results["error"] = str(e_scan)
                        unit_data_for_results["fc_scan_status"] = "error"

                    ip_scan_data["units"].append(unit_data_for_results)

                    # Final update for this unit in the live table
                    temp_table = Table(title=current_title) # Recreate to ensure clean state for Live
                    temp_table.add_column("Unit ID", style="dim", width=10)
                    temp_table.add_column("Status", width=25) # Increased width for longer status
                    temp_table.add_column("FC Support", width=30)
                    temp_table.add_column("Details", no_wrap=False)
                    for uid_disp in sorted(live_unit_display_data.keys()):
                        status, fc_str, details_str_val = live_unit_display_data[uid_disp]
                        temp_table.add_row(str(uid_disp), status, fc_str, details_str_val)
                    live.update(temp_table)

                # After all units for this IP are done, print a final static table for this IP
                # if config.get("verbose", 0) >= 1 or ip_scan_data["units"]: # Show if verbose or if units found/attempted
                overall_progress.console.print(f"\n[bold underline]Summary for IP: {ip}[/bold underline]")
                final_ip_table = Table(title=f"Final Results for {ip}")
                final_ip_table.add_column("Unit ID", style="dim", width=10)
                final_ip_table.add_column("Status", width=25)
                final_ip_table.add_column("FC Support", width=30)
                final_ip_table.add_column("Details", no_wrap=False)
                for unit_res in ip_scan_data["units"]:
                    uid = unit_res["unit_id"]
                    status_val, fc_str_val, details_val = live_unit_display_data.get(uid, ["Unknown", "", "Data missing"])
                    if "error" in unit_res:
                        status_val = "[red]Error[/red]"
                        details_val = f"[dim]{unit_res['error'][:100]}[/dim]"
                    elif unit_res.get("fc_support"):
                        supported = [fc for fc, sup in unit_res["fc_support"].items() if sup]
                        fc_str_val = ", ".join([f"FC{fc}" for fc in supported]) if supported else "None"
                        status_val = "[green]Checked[/green]"
                    final_ip_table.add_row(str(uid), status_val, fc_str_val, details_val)
                overall_progress.console.print(final_ip_table)

            await connector.disconnect()
            all_results.append(ip_scan_data)
            overall_progress.advance(ip_scan_task)

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
