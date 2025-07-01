# Modbus TCP Reconnaissance and Enumeration Tool

This project aims to create a professional-grade Modbus TCP reconnaissance and enumeration script.

## Features (Planned)

*   **Device Discovery**: Automatically discover Modbus TCP devices across a specified IP or range.
*   **Fingerprinting**:
    *   Identify active Unit IDs (1–247).
    *   Check for valid function code support (FC 1, 2, 3, 4).
    *   Vendor identification (if possible).
    *   Number of registers supported.
    *   Response times.
    *   Session anomalies (timeouts, error codes, illegal function access).
*   **Data Enumeration**:
    *   Enumerate valid register ranges using adaptive scanning.
    *   Dump Coil status (FC 1), Discrete inputs (FC 2), Holding registers (FC 3), Input registers (FC 4).
*   **Intelligent Parsing**:
    *   Check for byte/word swaps, endianness.
    *   Recognize common values (e.g., device state, time, temperature).
*   **Output**:
    *   Store results in CSV and JSON formats.
    *   Optional: Generate an HTML report or Markdown summary.
*   **User Interface**:
    *   Terminal-based UI (using Python `rich`) with color-coded output, progress bars, and smart error handling.
    *   Ability to stop/pause/resume scanning.
*   **Intelligence Features**:
    *   Adaptive register range discovery.
    *   Auto-delay to prevent flooding.
    *   Parallel scanning (`asyncio`).
*   **Configuration**:
    *   External YAML configuration file for scan options.

## Setup

1.  Clone the repository.
2.  Create a virtual environment: `python -m venv venv`
3.  Activate the virtual environment:
    *   Windows: `venv\\Scripts\\activate`
    *   macOS/Linux: `source venv/bin/activate`
4.  Install dependencies: `pip install -r requirements.txt`

## Usage (Planned)

```bash
python -m modbus_scanner <target_ip_or_range> [options]
```

Example:

```bash
python -m modbus_scanner 192.168.1.10
python -m modbus_scanner 192.168.1.1-100 -p 5020 --unit-ids 1,5,10-20
python -m modbus_scanner 10.0.0.0/24 --config custom_config.yml
```

## Project Structure

```
modbus_scanner/
├── modbus_scanner/         # Main package directory
│   ├── __init__.py
│   ├── main.py             # Main script entry point
│   ├── core/               # Core Modbus communication and scanning logic
│   │   ├── __init__.py
│   │   ├── connector.py
│   │   └── scanner.py
│   ├── utils/              # Utility functions (config loading, logging, etc.)
│   │   ├── __init__.py
│   │   ├── config_loader.py
│   │   └── logger_setup.py
│   ├── output/             # Output generation (CSV, JSON, HTML)
│   │   ├── __init__.py
│   │   └── writers.py
│   ├── ui/                 # User interface (TUI, GUI)
│   │   ├── __init__.py
│   │   └── tui_manager.py
│   ├── config/             # Default configurations
│   │   ├── __init__.py
│   │   └── config.yml      # Default configuration file
│   └── tests/              # Test suite
│       └── __init__.py
├── requirements.txt        # Project dependencies
├── README.md               # This file
├── AGENTS.md               # Instructions for AI agents
└── venv/                   # Virtual environment (if created locally)
```

## Contributing

Details TBD.

## License

Details TBD.
