# main.py
"""
Modbus TCP Reconnaissance and Enumeration Script

This script provides functionalities to discover, fingerprint, and enumerate
Modbus TCP devices on a network.
"""

import argparse
import logging
import yaml

from rich.console import Console
from rich.logging import RichHandler

# Placeholder for future imports
# from .core import scanner, connector
# from .utils import config_loader, logger_setup
# from .output import writer
# from .ui import tui_manager

# Initialize Rich Console for beautiful output
console = Console()

# Setup basic logging
# More advanced setup will be in utils/logger_setup.py
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("rich")

def main():
    """
    Main function to parse arguments and initiate scanning.
    """
    parser = argparse.ArgumentParser(
        description="Modbus TCP Reconnaissance and Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        help="Target IP address, IP range (e.g., 192.168.1.1-100), or CIDR (e.g., 192.168.1.0/24)."
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=502,
        help="Modbus TCP port to scan (default: 502)."
    )
    parser.add_argument(
        "-u", "--unit-ids",
        default="1-247",
        help="Unit IDs to scan, comma-separated or range (e.g., 1,2,3 or 1-10, default: 1-247)."
    )
    parser.add_argument(
        "-c", "--config",
        default="config/config.yml",
        help="Path to the configuration file (default: config/config.yml)."
    )
    parser.add_argument(
        "-o", "--output-prefix",
        default="scan_results",
        help="Prefix for output files (e.g., 'scan_results' -> scan_results.json, scan_results.csv)."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)."
    )
    parser.add_argument(
        "--fast-scan",
        action="store_true",
        help="Perform a faster scan by limiting register checks (good for initial discovery)."
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (e.g., -v, -vv, -vvv)."
    )

    args = parser.parse_args()

    if args.no_color:
        global console
        console = Console(no_color=True)
        # Re-configure logger if necessary or handle color in RichHandler

    # Adjust logging level based on verbosity
    if args.verbose == 1:
        logger.setLevel(logging.DEBUG)
    elif args.verbose >= 2:
        # Pymodbus can be very noisy at DEBUG, so INFO for it, DEBUG for our app
        logging.getLogger("pymodbus").setLevel(logging.INFO)
        logger.setLevel(logging.DEBUG)


    logger.info(f"Starting Modbus Scanner against target: [bold cyan]{args.target}[/bold cyan] on port [bold cyan]{args.port}[/bold cyan]")

    # --- Configuration Loading (Placeholder) ---
    try:
        with open(args.config, 'r') as f:
            config_options = yaml.safe_load(f)
        logger.info(f"Loaded configuration from: [green]{args.config}[/green]")
        # Merge args and config_options, args take precedence
    except FileNotFoundError:
        logger.warning(f"Configuration file not found at: [yellow]{args.config}[/yellow]. Using defaults and command-line arguments.")
        config_options = {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration file: {e}")
        return

    # --- Actual Scanning Logic (Placeholder) ---
    logger.info("Scanning logic not yet implemented.")
    console.print(f"Target: {args.target}")
    console.print(f"Port: {args.port}")
    console.print(f"Unit IDs: {args.unit_ids}")
    console.print(f"Config File: {args.config}")
    console.print(f"Output Prefix: {args.output_prefix}")
    console.print(f"Timeout: {args.timeout}")
    console.print(f"Fast Scan: {args.fast_scan}")
    console.print(f"Verbosity: {args.verbose}")


    # Example of using rich
    console.rule("[bold red]Scan Complete[/bold red]")
    logger.info("Modbus Scan Finished.")

if __name__ == "__main__":
    main()
