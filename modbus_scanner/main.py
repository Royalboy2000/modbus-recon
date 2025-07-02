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


    # console.rule("[bold blue]Initiating Scan[/bold blue]") # Replaced by Layout
    all_results = []

    # --- Actual Scanning Logic ---
    from modbus_scanner.core.connector import ModbusConnector
    from modbus_scanner.core.scanner import ModbusScanner
    from rich.live import Live
    from rich.table import Table, Column # Added Column
    from rich.layout import Layout
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn
    from rich.panel import Panel

    # Define Layout
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=1), # Reduced header size
        Layout(name="main_scan", ratio=1),
        Layout(name="footer", size=1)
    )
    layout["main_scan"].split_row(
        Layout(name="ip_progress_region", ratio=1),
        Layout(name="unit_details_region", ratio=2)
    )

    layout["header"].update(Panel("[bold blue]Modbus Scanner[/bold blue] - Initializing...", expand=True, border_style="dim blue"))
    layout["footer"].update(Panel("Status: Preparing scan...", expand=True, border_style="dim blue"))

    # Define columns for Progress explicitly for clarity and correct argument passing
    progress_columns = [
        TextColumn("[progress.description]{task.description}", table_column=Column(width=35)), # Use Column object
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"), # Show one decimal for percentage
        TimeRemainingColumn(),
        TimeElapsedColumn(), # Added for more info
    ]
    overall_progress_display = Progress(
        *progress_columns,
        console=console,
        transient=False
    )
    ip_scan_task = overall_progress_display.add_task("[cyan]Overall Progress[/cyan]", total=len(ip_targets))
    layout["main_scan"]["ip_progress_region"].update(Panel(overall_progress_display, title="[b]Scan Progress[/b]", border_style="green", padding=(1,1)))

    initial_unit_panel_content = Table(title="Waiting for IP scan...")
    initial_unit_panel_content.add_column("Info")
    initial_unit_panel_content.add_row("Select target and start scan.")
    layout["main_scan"]["unit_details_region"].update(Panel(initial_unit_panel_content, title="[b]Unit Details[/b]", border_style="blue"))


    with Live(layout, console=console, refresh_per_second=10, screen=False, transient=False) as live:
        layout["footer"].update(Panel("Status: Scanning IPs...", expand=True, border_style="yellow"))

        for ip_index, ip in enumerate(ip_targets):
            layout["header"].update(Panel(f"[bold blue]Modbus Scanner[/bold blue] - Current Target: [cyan]{ip}[/cyan] ({ip_index+1}/{len(ip_targets)})", expand=True, border_style="blue"))
            overall_progress_display.update(ip_scan_task, description=f"Scanning: {ip}")
            # No need to update layout[\"main_scan\"][\"ip_progress_region\"] directly if overall_progress_display object itself is updated and part of layout

            ip_scan_data = {"ip": ip, "port": config.get('port'), "units": []}

            current_ip_unit_rows_data = {}
            unit_display_table = Table(title=f"Units for {ip}")
            unit_display_table.add_column("ID", style="dim", width=5)
            unit_display_table.add_column("Status", width=18)
            unit_display_table.add_column("FCs Supported", width=28)
            unit_display_table.add_column("Dump Summary / Error", no_wrap=False)
            layout["main_scan"]["unit_details_region"].update(Panel(unit_display_table, title=f"[b]Unit Scan: {ip}[/b]", border_style="blue"))
            live.refresh()

            connector = ModbusConnector(
                host=ip,
                port=int(config.get('port', 502)),
                timeout=float(config.get('timeout', 1.0))
            )

            if not await connector.connect():
                message = f"Failed to connect to {ip}:{config.get('port')}"
                logger.warning(message)
                layout["main_scan"]["unit_details_region"].update(Panel(f"[bold red]Connection Failed[/bold red]\n{message}", title=f"Error: {ip}", border_style="red"))
                ip_scan_data["status"] = "connection_failed"
                all_results.append(ip_scan_data)
                overall_progress_display.advance(ip_scan_task)
                # layout["main_scan"]["ip_progress_region"].update(overall_progress_display) # Already part of live, auto-refreshes
                await asyncio.sleep(0.2)
                continue

            logger.info(f"Successfully connected to {ip}:{config.get('port')}")
            ip_scan_data["status"] = "connected"

            for unit_idx, unit_id in enumerate(unit_ids_to_scan):
                unit_id_str = str(unit_id)
                current_ip_unit_rows_data[unit_id] = [unit_id_str, "[cyan]Probing FCs...[/cyan]", "", ""]

                temp_unit_table = Table(title=f"Units for {ip} (Unit {unit_id_str} - {unit_idx+1}/{len(unit_ids_to_scan)})")
                temp_unit_table.add_column("ID", style="dim", width=5); temp_unit_table.add_column("Status", width=18)
                temp_unit_table.add_column("FCs Supported", width=28); temp_unit_table.add_column("Dump Summary / Error", no_wrap=False)
                for uid_key in sorted(current_ip_unit_rows_data.keys()):
                    temp_unit_table.add_row(*current_ip_unit_rows_data[uid_key])
                layout["main_scan"]["unit_details_region"].update(Panel(temp_unit_table, title=f"[b]Unit Scan: {ip}[/b]", border_style="blue"))
                await asyncio.sleep(0.02)

                unit_data_for_results = {"unit_id": unit_id}
                fc_support_str_val = "[red]N/A[/red]"
                details_str_val = ""
                status_str_val = "[red]Error[/red]"

                try:
                    client = connector.get_client()
                    if not client:
                        error_msg = "Client unavailable"
                        logger.error(f"Unit {unit_id} on {ip}: {error_msg}")
                        status_str_val, details_str_val = "[red]Client Err[/red]", error_msg
                        unit_data_for_results["error"] = error_msg
                    else:
                        modbus_scanner = ModbusScanner(client=client, unit_id=unit_id)
                        fc_support = await modbus_scanner.check_function_code_support()
                        unit_data_for_results["fc_support"] = fc_support
                        supported_fcs = [fc for fc, sup_val in fc_support.items() if sup_val]
                        fc_support_str_val = ", ".join([f"FC{fc}" for fc in supported_fcs]) if supported_fcs else "[yellow]None[/yellow]"
                        status_str_val = "[green]FCs Checked[/green]"

                        if supported_fcs:
                            unit_data_for_results["data_dumps"] = {}
                            dump_details_parts = []
                            status_str_val = "[yellow]Dumping...[/yellow]"
                            current_ip_unit_rows_data[unit_id] = [unit_id_str, status_str_val, fc_support_str_val, ""]

                            _dumping_table = Table(title=f"Units for {ip} (Dumping {unit_id_str} - {unit_idx+1}/{len(unit_ids_to_scan)})")
                            _dumping_table.add_column("ID", style="dim", width=5); _dumping_table.add_column("Status", width=18)
                            _dumping_table.add_column("FCs Supported", width=28); _dumping_table.add_column("Dump Summary / Error", no_wrap=False)
                            for _uid_k in sorted(current_ip_unit_rows_data.keys()): _dumping_table.add_row(*current_ip_unit_rows_data[_uid_k])
                            layout["main_scan"]["unit_details_region"].update(Panel(_dumping_table, title=f"[b]Unit Scan: {ip}[/b]", border_style="blue"))
                            await asyncio.sleep(0.02)

                            for fc_to_dump in supported_fcs:
                                dump_result = await modbus_scanner.discover_valid_ranges_and_dump(
                                    fc=fc_to_dump,
                                    max_addr=config.get('max_coil_address', 9999) if fc_to_dump in [1,2] else config.get('max_register_address', 9999)
                                )
                                unit_data_for_results["data_dumps"][f"fc{fc_to_dump}"] = dump_result
                                if dump_result["status"] == "success" and dump_result["valid_ranges"]:
                                    num_items = sum(len(r.get("values", [])) for r in dump_result["valid_ranges"])
                                    dump_details_parts.append(f"FC{fc_to_dump}:{num_items}")
                                elif dump_result["status"] == "success_no_data":
                                    dump_details_parts.append(f"FC{fc_to_dump}:NoData")
                                else:
                                    dump_details_parts.append(f"FC{fc_to_dump}:{dump_result['status'][:5]}")
                            details_str_val = "; ".join(dump_details_parts)
                            status_str_val = "[green]Dumped[/green]" if dump_details_parts else "[yellow]Dumped (N/A)[/yellow]"
                        else:
                            details_str_val = "No FCs to dump"
                            unit_data_for_results["data_dumps"] = "skipped_no_fc_support"

                except Exception as e_scan:
                    error_msg_short = f"ERR: {type(e_scan).__name__}"
                    logger.error(f"Unit {unit_id} on {ip}: {error_msg_short} - {str(e_scan)[:100]}...", exc_info=True)
                    details_str_val = f"[dim]{str(e_scan)[:50]}[/dim]"
                    unit_data_for_results["error"] = str(e_scan)

                current_ip_unit_rows_data[unit_id] = [unit_id_str, status_str_val, fc_support_str_val, details_str_val]
                ip_scan_data["units"].append(unit_data_for_results)

                final_unit_table = Table(title=f"Units for {ip} (Processed Unit {unit_id_str} - {unit_idx+1}/{len(unit_ids_to_scan)})")
                final_unit_table.add_column("ID", style="dim", width=5); final_unit_table.add_column("Status", width=18)
                final_unit_table.add_column("FCs Supported", width=28); final_unit_table.add_column("Dump Summary / Error", no_wrap=False)
                for uid_key_final in sorted(current_ip_unit_rows_data.keys()):
                    final_unit_table.add_row(*current_ip_unit_rows_data[uid_key_final])
                layout["main_scan"]["unit_details_region"].update(Panel(final_unit_table, title=f"[b]Unit Scan: {ip}[/b]", border_style="blue"))

            layout["main_scan"]["unit_details_region"].update(Panel(f"Finished scanning units for [cyan]{ip}[/cyan].\n"
                                                     f"{len(ip_scan_data['units'])} units processed. Results stored.",
                                                     title=f"IP {ip} Scan Summary", border_style="green"))
            await connector.disconnect()
            all_results.append(ip_scan_data)
            overall_progress_display.advance(ip_scan_task)
            # layout["main_scan"]["ip_progress_region"].update(overall_progress_display) # Progress bar updates itself
            if ip_index < len(ip_targets) - 1:
                await asyncio.sleep(0.5)

        layout["footer"].update(Panel("[bold green]Status: Scan Complete![/bold green]", expand=True, border_style="green"))
        layout["header"].update(Panel("[bold blue]Modbus Scanner[/bold blue] - Scan Finished", expand=True, border_style="dim blue"))

    console.rule("[bold red]Overall Scan Complete[/bold red]")
    logger.info("Modbus Scan Main Loop Finished.")

    if all_results:
        logger.info("Attempting to write output files...")
        output_prefix = config.get("output_prefix", "scan_results")
        json_filename = f"{output_prefix}.json"
        csv_filename = f"{output_prefix}_summary.csv"

        from modbus_scanner.output import writers # Import here to avoid circular if utils also import from output

        if writers.write_json_output(all_results, json_filename):
            console.print(f"JSON results saved to [bold green]{json_filename}[/bold green]")
        else:
            console.print(f"[bold red]Failed to save JSON results to {json_filename}[/bold red]")

        if writers.write_summary_csv_output(all_results, csv_filename):
            console.print(f"CSV summary saved to [bold green]{csv_filename}[/bold green]")
        else:
            console.print(f"[bold red]Failed to save CSV summary to {csv_filename}[/bold red]")

        # Optional: Pretty print to console if not too large or if verbose
        # if len(str(all_results)) < 3000: # Arbitrary limit to avoid flooding console
        #    console.print("\n[bold green]Collected Results (Full Data):[/bold green]")
        #    from rich.pretty import pprint
        #    pprint(all_results)
        # else:
        #    console.print("\n[bold green]Collected Results (Full Data written to files).[/bold green]")

    else:
        logger.info("No results collected to write.")


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
    parser.add_argument(
        "--max-register-address",
        type=int,
        default=None,
        metavar="ADDR",
        help="Highest register address (FC3, FC4) to scan. Overrides config. (Default: from config or 9999)"
    )
    parser.add_argument(
        "--max-coil-address",
        type=int,
        default=None,
        metavar="ADDR",
        help="Highest coil/discrete input address (FC1, FC2) to scan. Overrides config. (Default: from config or 9999)"
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
