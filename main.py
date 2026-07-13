# ==========================================================
# Project : Network Traffic Detection System
# File    : main.py
# Author  : Pradeep Tunga
# Purpose : Start the Network Traffic Detection System
# ==========================================================

# Import project information
from config import PROJECT_NAME, VERSION, AUTHOR

# Import packet capture function
from packet_capture import start_capture


def main():
    """
    Main function of the project.
    """

    print("=" * 60)
    print(PROJECT_NAME)
    print("Version :", VERSION)
    print("Author  :", AUTHOR)
    print("=" * 60)

    # Start capturing packets
    start_capture()


# Run the program only if this file is executed directly
if __name__ == "__main__":
    main()