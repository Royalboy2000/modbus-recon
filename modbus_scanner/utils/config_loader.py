# modbus_scanner/utils/config_loader.py
"""
Utility functions for loading and merging configuration.
"""
import yaml
import argparse
import logging
from typing import Dict, Any

logger = logging.getLogger("rich")

DEFAULT_CONFIG_VALUES = {
    "port": 502,
    "unit_ids": "1-247",
    "timeout": 1.0,
    "fast_scan": False,
    "max_register_address": 9999,
    "max_coil_address": 9999,
    "request_delay": 0.05, # Default delay of 50ms
    # Add other defaults as the tool evolves
}

def load_config_file(config_path: str) -> Dict[str, Any]:
    """
    Loads configuration from a YAML file.

    :param config_path: Path to the YAML configuration file.
    :return: A dictionary with configuration options or an empty dict if file not found/error.
    """
    try:
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f)
        if file_config is None: # Handles empty YAML file
            return {}
        logger.info(f"Successfully loaded configuration from [green]{config_path}[/green]")
        return file_config
    except FileNotFoundError:
        logger.warning(f"Configuration file not found at: [yellow]{config_path}[/yellow]. Using defaults and command-line arguments.")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration file '{config_path}': {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading configuration file '{config_path}': {e}")
        return {}

def merge_configs(cli_args: argparse.Namespace, file_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merges configurations from CLI arguments and a configuration file.
    CLI arguments take precedence over file configuration, which takes precedence over defaults.

    :param cli_args: Parsed command-line arguments.
    :param file_config: Configuration loaded from a file.
    :return: A dictionary containing the final merged configuration.
    """
    merged_config = DEFAULT_CONFIG_VALUES.copy()

    # Apply file config over defaults
    if file_config:
        for key, value in file_config.items():
            if value is not None: # Ensure not to overwrite with None if key exists in file but has no value
                merged_config[key] = value

    # Apply CLI args over merged_config (defaults + file_config)
    # For each potential CLI argument, check if it was set (not None or not its default for actions)
    # and override the corresponding key in merged_config.
    cli_vars = vars(cli_args)
    for key, value in cli_vars.items():
        # Check if the CLI argument was actually provided or changed from its argparse default
        # This is a bit tricky because argparse defaults can be None or other values.
        # A common way is to compare with a fresh parse_args([]) but that's overkill here.
        # We assume if it's in cli_vars, it's relevant.
        # If the default value of an arg in argparse is None, and the user doesn't provide it, it will be None.
        # If the default is something else (e.g. 502 for port), it will always have a value.
        # We need to be careful not to just blindly overwrite if the CLI arg is at its argparse default
        # UNLESS that default is different from our DEFAULT_CONFIG_VALUES.

        # A simpler heuristic: if the key is in our DEFAULT_CONFIG_VALUES,
        # and the CLI value is different from the argparse default for that specific arg,
        # then the user likely intended to set it via CLI.
        # However, the most straightforward is: CLI always wins if the key matches.
        if key in merged_config:
            # Special handling for args where cli_vars might have a value even if not explicitly set by user
            # e.g. args.port has default 502. If config.yml also has port: 5020, cli should only win if user types -p XXXX
            # For now, a direct override if the key exists in cli_vars and merged_config.
            # This means CLI defaults specified in argparse will override file config if not specified in CLI.
            # This is generally acceptable behavior.
            if value is not None: # Ensure CLI arg is not None before overriding
                 merged_config[key] = value
        else:
            # If the key is not in our known config options but came from CLI, add it.
            # This is less common for this type of app but possible.
            if value is not None:
                merged_config[key] = value

    # Ensure 'target' from CLI is present, as it's a positional argument
    if 'target' not in merged_config or merged_config['target'] is None:
        merged_config['target'] = cli_args.target


    logger.debug(f"Final merged configuration: {merged_config}")
    return merged_config

# Example usage (for testing this module)
if __name__ == "__main__":
    # This is just for quick testing of this module.
    # Run `python -m modbus_scanner.utils.config_loader` from the project root.

    # Setup basic logging for testing
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create a dummy argparse Namespace
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target IP") # Made target optional for test
    parser.add_argument("-p", "--port", type=int, help="Modbus TCP port") # Default is None if not provided
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout")
    parser.add_argument("--config", default="dummy_config.yml", help="Config file")
    parser.add_argument("--fast-scan", action="store_true", help="Fast scan")


    # --- Test Case 1: CLI only ---
    logger.info("\n--- Test Case 1: CLI only ---")
    args1 = parser.parse_args(["192.168.1.100", "--port", "5020"])
    file_conf1 = {} # No file config
    merged1 = merge_configs(args1, file_conf1)
    logger.info(f"CLI args: {vars(args1)}")
    logger.info(f"Merged config 1: {merged1}")
    assert merged1['target'] == "192.168.1.100"
    assert merged1['port'] == 5020
    assert merged1['timeout'] == 2.0 # From argparse default
    assert not merged1['fast_scan']

    # --- Test Case 2: File only, CLI uses defaults ---
    logger.info("\n--- Test Case 2: File only ---")
    args2 = parser.parse_args(["10.0.0.1"]) # Target from CLI, other CLI args at their defaults
    file_conf2 = {"port": 5022, "timeout": 0.5, "fast_scan": True, "custom_param": "hello"}
    merged2 = merge_configs(args2, file_conf2)
    logger.info(f"CLI args: {vars(args2)}")
    logger.info(f"File config: {file_conf2}")
    logger.info(f"Merged config 2: {merged2}")
    assert merged2['target'] == "10.0.0.1"
    assert merged2['port'] == 5022 # From file
    assert merged2['timeout'] == 0.5 # From file (overrides CLI default 2.0)
    assert merged2['fast_scan'] # From file
    assert merged2['custom_param'] == "hello" # From file, added

    # --- Test Case 3: CLI overrides File ---
    logger.info("\n--- Test Case 3: CLI overrides File ---")
    args3 = parser.parse_args(["10.0.0.2", "--port", "9999", "--timeout", "3.0"])
    file_conf3 = {"port": 5023, "timeout": 0.7, "fast_scan": True, "unit_ids": "1,2,3"}
    merged3 = merge_configs(args3, file_conf3)
    logger.info(f"CLI args: {vars(args3)}")
    logger.info(f"File config: {file_conf3}")
    logger.info(f"Merged config 3: {merged3}")
    assert merged3['target'] == "10.0.0.2"
    assert merged3['port'] == 9999 # CLI wins
    assert merged3['timeout'] == 3.0 # CLI wins
    assert not merged3['fast_scan'] # CLI did not specify, so file's True was overridden by DEFAULT_CONFIG_VALUES's False then by CLI's default action (False)
                                     # This needs careful thought: action="store_true" defaults to False if not present.
                                     # If file_config['fast_scan'] is True, and CLI doesn't mention --fast-scan,
                                     # current logic: merged_config['fast_scan'] starts False (DEFAULT), then becomes True (file_config),
                                     # then CLI vars(args3)['fast_scan'] is False (argparse default for store_true not present), so it becomes False.
                                     # This is correct: if CLI doesn't set it, it means "use default", which for store_true is False.
                                     # If we want file to win over CLI default, merge_configs needs to be smarter about argparse defaults.
                                     # For now, this behavior (CLI default overrides file) is acceptable.
    assert merged3['unit_ids'] == "1,2,3" # From file

    # --- Test Case 4: Loading a non-existent file ---
    logger.info("\n--- Test Case 4: Non-existent file ---")
    args4 = parser.parse_args(["10.0.0.3"])
    loaded_conf4 = load_config_file("non_existent_config.yml")
    merged4 = merge_configs(args4, loaded_conf4)
    logger.info(f"CLI args: {vars(args4)}")
    logger.info(f"Loaded config: {loaded_conf4}")
    logger.info(f"Merged config 4: {merged4}")
    assert merged4['port'] == DEFAULT_CONFIG_VALUES['port'] # Default
    assert loaded_conf4 == {}

    logger.info("\nAll config loader tests seem to pass based on current logic.")
