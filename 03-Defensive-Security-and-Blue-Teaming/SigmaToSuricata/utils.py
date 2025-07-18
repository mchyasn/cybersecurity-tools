import re

def sanitize_sid(input_str):
    """Create a numeric SID from rule ID or fallback string"""
    if isinstance(input_str, str):
        digits = ''.join(filter(str.isdigit, input_str))
        return int(digits[:7]) if digits else 1000000
    elif isinstance(input_str, int):
        return input_str
    return 1000000
