# ==========================================================
# Project : Network Traffic Detection System
# File    : protocol_utils.py
# Author  : Pradeep Tunga
# Purpose : Convert protocol numbers into protocol names
# ==========================================================


def get_protocol_name(protocol_number):
    """
    Convert protocol number to protocol name.

    Parameters:
        protocol_number (int): Protocol number from the IP header.

    Returns:
        str: Protocol name.
    """

    if protocol_number == 6:
        return "TCP"

    elif protocol_number == 17:
        return "UDP"

    elif protocol_number == 1:
        return "ICMP"

    elif protocol_number == 2:
        return "IGMP"

    else:
        return f"Unknown ({protocol_number})"