# ark_project/test_ark.py
import logging # Import logging

# --- Basic Logging Configuration ---
# Set the logging level (e.g., INFO, DEBUG) and format for messages
# This configures the root logger, which autork's logger will inherit from
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG to see more detailed messages
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Optional: Silence overly verbose libraries if needed (e.g., if you add libraries later)
# logging.getLogger("some_verbose_library").setLevel(logging.WARNING)
# ------------------------------------

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from typing import List

def main():
    # No need to change the rest of main, it will now show logs instead of prints from autork
    logging.info("--- Testing ARKEngine (with OS Detection) ---") # Use logging here too

    engine = ARKEngine()
    test_target_scope = "scanme.nmap.org"
    should_include_os = True

    logging.info(f"Starting reconnaissance with ARKEngine on: {test_target_scope}")
    if should_include_os:
        logging.warning("OS Detection is ENABLED. This may require elevated privileges (sudo/admin).") # Use warning level

    recon_results: List[Host] = engine.perform_basic_recon(
        test_target_scope,
        top_ports=20,
        include_os_detection=should_include_os
    )

    if recon_results:
        print("\n\n--- ARKEngine Reconnaissance Summary ---") # Keep prints for final user output
        # ... (rest of the printing logic remains the same) ...

if __name__ == '__main__':
    main()