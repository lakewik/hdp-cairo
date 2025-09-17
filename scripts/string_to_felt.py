#!/usr/bin/env python3
"""
Script to convert a string to a Cairo0 felt252 representation.
This is useful for creating felt values from strings in Cairo.
"""

import sys
from typing import Union

def string_to_felt(s: str) -> str:
    """
    Convert a string to a felt252 representation.
    
    Args:
        s: Input string
        
    Returns:
        str: Hex representation of the felt252 value
    """
    if not isinstance(s, str):
        raise ValueError("Input must be a string")
    
    # Convert string to bytes using UTF-8 encoding
    bytes_data = s.encode('utf-8')
    
    # Convert bytes to integer (big-endian)
    felt_value = int.from_bytes(bytes_data, 'big')
    
    # Ensure it fits in felt252 (252 bits)
    max_felt = (1 << 252) - 1
    if felt_value > max_felt:
        raise ValueError(f"String too long to fit in felt252. Max value: {max_felt}")
    
    return hex(felt_value)

def felt_to_string(felt_hex: Union[str, int]) -> str:
    """
    Convert a felt252 back to a string.
    
    Args:
        felt_hex: Felt value as hex string or integer
        
    Returns:
        str: Original string
    """
    # Convert to integer
    if isinstance(felt_hex, str):
        if felt_hex.startswith('0x'):
            felt_value = int(felt_hex, 16)
        else:
            felt_value = int(felt_hex, 16)
    else:
        felt_value = felt_hex
    
    # Ensure it's within felt252 range
    max_felt = (1 << 252) - 1
    if felt_value < 0 or felt_value > max_felt:
        raise ValueError(f"Felt value must be within range (0 to {max_felt})")
    
    # Convert to bytes
    # Calculate minimum number of bytes needed
    if felt_value == 0:
        return ""
    
    byte_length = (felt_value.bit_length() + 7) // 8
    bytes_data = felt_value.to_bytes(byte_length, 'big')
    
    # Remove leading null bytes that might have been added
    bytes_data = bytes_data.lstrip(b'\x00')
    
    # Convert back to string
    try:
        return bytes_data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Felt value does not represent a valid UTF-8 string")

def string_to_felt_array(s: str, max_length: int = 31) -> list:
    """
    Convert a long string to an array of felt252 values.
    Each felt can hold up to 31 characters (248 bits / 8 bits per char).
    
    Args:
        s: Input string
        max_length: Maximum characters per felt (default 31)
        
    Returns:
        list: Array of hex felt values
    """
    if not isinstance(s, str):
        raise ValueError("Input must be a string")
    
    felts = []
    
    # Split string into chunks
    for i in range(0, len(s), max_length):
        chunk = s[i:i + max_length]
        felt = string_to_felt(chunk)
        felts.append(felt)
    
    return felts

def felt_array_to_string(felt_array: list) -> str:
    """
    Convert an array of felt252 values back to a string.
    
    Args:
        felt_array: Array of felt values (hex strings or integers)
        
    Returns:
        str: Reconstructed string
    """
    result = ""
    
    for felt in felt_array:
        chunk = felt_to_string(felt)
        result += chunk
    
    return result

def main():
    """Interactive demo of the conversion functions."""
    print("String to Felt252 Converter")
    print("=" * 50)
    
    # Example strings
    examples = [
        "Hello",
        "Hello, World!",
        "Cairo",
        "felt252",
        "0x123",
        "🚀",
        "中文",
        "A" * 31,  # Exactly 31 characters
        "A" * 32,  # 32 characters (needs array)
        "This is a very long string that will definitely need to be split into multiple felt values because it exceeds the maximum length that can fit in a single felt252.",
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\nExample {i}:")
        print(f"Input string: '{example}'")
        print(f"Length: {len(example)} characters")
        
        try:
            if len(example) <= 31:
                # Single felt
                felt = string_to_felt(example)
                print(f"Single felt: {felt}")
                
                # Verify round-trip
                reconstructed = felt_to_string(felt)
                print(f"Reconstructed: '{reconstructed}'")
                print(f"Match: {example == reconstructed}")
            else:
                # Multiple felts
                felts = string_to_felt_array(example)
                print(f"Felt array ({len(felts)} felts):")
                for j, felt in enumerate(felts):
                    print(f"  [{j}]: {felt}")
                
                # Verify round-trip
                reconstructed = felt_array_to_string(felts)
                print(f"Reconstructed: '{reconstructed}'")
                print(f"Match: {example == reconstructed}")
                
        except ValueError as e:
            print(f"Error: {e}")
    
    # Interactive mode
    print("\n" + "=" * 50)
    print("Interactive mode (enter 'quit' to exit):")
    
    while True:
        try:
            user_input = input("\nEnter string to convert: ").strip()
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
                
            if not user_input:
                continue
            
            print(f"Input: '{user_input}'")
            print(f"Length: {len(user_input)} characters")
            
            if len(user_input) <= 31:
                felt = string_to_felt(user_input)
                print(f"Felt: {felt}")
            else:
                felts = string_to_felt_array(user_input)
                print(f"Felt array ({len(felts)} felts):")
                for i, felt in enumerate(felts):
                    print(f"  [{i}]: {felt}")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
