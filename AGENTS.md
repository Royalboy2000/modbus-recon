## Agent Instructions for Modbus Scanner Project

Welcome, Jules! This file contains guidelines and instructions for working on the Modbus Scanner project.

### Project Goal

To create a professional-grade Modbus TCP reconnaissance and enumeration script with features like device discovery, fingerprinting, data enumeration, intelligent parsing, rich TUI, and flexible output formats.

### Coding Conventions

1.  **Language**: Python 3.9+
2.  **Style Guide**: Follow PEP 8. Use a linter like Flake8 or a formatter like Black if possible (though you'll be applying changes via diffs).
3.  **Type Hinting**: Use type hints for all function signatures and critical variables.
4.  **Docstrings**: Write clear and concise docstrings for all modules, classes, and functions (Google Python Style Guide format preferred).
5.  **Modularity**: Design components to be modular and testable.
6.  **Error Handling**: Implement robust error handling. Use specific exceptions where appropriate.
7.  **Logging**: Use the `logging` module for application logs. Leverage `rich.logging.RichHandler` for user-facing console output.
8.  **Dependencies**: Keep `requirements.txt` updated. Add comments for non-obvious choices or version constraints.
9.  **Configuration**: Store configurable parameters in a YAML file (`config/config.yml`). Command-line arguments should override config file settings.

### Development Workflow

1.  **Plan First**: Before writing significant code, update the plan using `set_plan`.
2.  **Incremental Steps**: Implement features in small, manageable steps.
3.  **Test (Eventually)**: While full TDD might be hard in this environment, think about how components will be tested. We will add tests later.
4.  **Commit Messages**: When submitting, use conventional commit message style if possible (e.g., `feat: add Modbus TCP connection logic`).

### Key Libraries

*   `pymodbus`: For Modbus communication. Familiarize yourself with its client API, especially for TCP. Note its exception classes.
*   `rich`: For the TUI. Explore its features for tables, progress bars, spinners, styled text, and logging.
*   `PyYAML`: For parsing the configuration file.
*   `argparse`: For command-line argument parsing.
*   `asyncio`: Will be used for concurrent scanning. Pay attention to how `pymodbus` handles asyncio.

### Specific Tasks & Considerations

*   **IP Address Handling**: Need a robust way to parse single IPs, ranges (e.g., 192.168.1.1-100), and CIDR notation (e.g., 192.168.1.0/24). The `ipaddress` module in Python's standard library is excellent for this.
*   **Unit ID Parsing**: Allow comma-separated lists and ranges for unit IDs.
*   **Adaptive Scanning**: The logic for adaptively scanning register ranges will be crucial. This means trying to read a block of registers, and if an "Illegal Data Address" error occurs, reducing the range or stopping for that specific unit ID/function code.
*   **Endianness and Data Parsing**: Modbus data can be tricky. Provide options or auto-detection for byte/word swapping. For common values, this will likely involve pattern matching or heuristics on register values.
*   **Error Codes**: Properly map Modbus exception codes to meaningful error messages.
*   **Output Formatting**: Ensure CSV and JSON outputs are well-structured and easy to parse.
*   **User Experience (TUI)**:
    *   Provide clear feedback on what the scanner is doing.
    *   Make it easy to see successes, failures, and important findings.
    *   Stopping/pausing/resuming: This is advanced. Initial versions might only support stopping (Ctrl+C). True pause/resume requires state management.

### What to Avoid

*   **Blocking Operations in UI/Async Code**: Be mindful of long-running operations that could freeze the TUI or block the asyncio event loop.
*   **Overly Aggressive Scanning**: Implement delays (configurable) to avoid overwhelming devices or networks. Start with conservative defaults.
*   **Hardcoding**: Avoid hardcoding IP addresses, ports, or extensive register lists. Use the configuration file.

### Initial Focus

1.  Get the basic project structure right.
2.  Implement core Modbus connection and basic read functions (FC1-4).
3.  Set up command-line argument parsing.
4.  Implement configuration file loading.
5.  Basic TUI output for progress and results.

Good luck! I'm looking forward to seeing this tool develop.Tool output for `create_file_with_block`:
