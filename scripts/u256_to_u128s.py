#!/usr/bin/env python3
"""
Simple script to divide one U256 into two U128 values.
This is useful for handling 256-bit values by splitting them into two 128-bit parts.
"""

def u256_to_u128s(u256_value):
    """
    Convert a U256 value to two U128 values.
    
    Args:
        u256_value: Can be int, hex string (with or without 0x), or bytes
        
    Returns:
        tuple: (high_u128, low_u128) where each is a hex string representation
    """
    # Convert input to integer
    if isinstance(u256_value, str):
        if u256_value.startswith('0x'):
            u256_value = int(u256_value, 16)
        else:
            u256_value = int(u256_value, 16)
    elif isinstance(u256_value, bytes):
        u256_value = int.from_bytes(u256_value, 'big')
    elif not isinstance(u256_value, int):
        raise ValueError("Input must be int, hex string, or bytes")
    
    # Ensure it's within U256 range
    if u256_value < 0 or u256_value >= 2**256:
        raise ValueError("Value must be within U256 range (0 to 2^256 - 1)")
    
    # Split at 128 bits
    # High part: bits 128-255 (128 bits)
    # Low part: bits 0-127 (128 bits)
    
    # Create mask for low 128 bits
    low_mask = (1 << 128) - 1
    
    # Extract low and high parts
    low_u128 = u256_value & low_mask
    high_u128 = u256_value >> 128
    
    return hex(high_u128), hex(low_u128)

def u128s_to_u256(high_u128, low_u128):
    """
    Convert two U128 values back to U256.
    
    Args:
        high_u128: High part as hex string or int
        low_u128: Low part as hex string or int
        
    Returns:
        str: U256 value as hex string
    """
    # Convert to integers
    if isinstance(high_u128, str):
        high_u128 = int(high_u128, 16)
    if isinstance(low_u128, str):
        low_u128 = int(low_u128, 16)
    
    # Ensure values are within U128 range
    if high_u128 < 0 or high_u128 >= 2**128:
        raise ValueError("High U128 value must be within range (0 to 2^128 - 1)")
    if low_u128 < 0 or low_u128 >= 2**128:
        raise ValueError("Low U128 value must be within range (0 to 2^128 - 1)")
    
    # Reconstruct U256
    u256_value = (high_u128 << 128) | low_u128
    
    return hex(u256_value)

def main():
    """Interactive demo of the conversion functions."""
    print("U256 to U128 Converter")
    print("=" * 40)
    
    # Example values
    examples = [
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0x1",
        "0x0",
        "0x10000000000000000000000000000000000000000000000000000000000000000",  # 2^128
        "0x1234567890abcdef1234567890abcdef00000000000000000000000000000000",  # High part only
        "0x000000000000000000000000000000001234567890abcdef1234567890abcdef",  # Low part only
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\nExample {i}:")
        print(f"Input U256: {example}")
        
        try:
            high_u128, low_u128 = u256_to_u128s(example)
            print(f"High U128:  {high_u128}")
            print(f"Low U128:   {low_u128}")
            
            # Verify round-trip conversion
            reconstructed = u128s_to_u256(high_u128, low_u128)
            print(f"Reconstructed: {reconstructed}")
            print(f"Match: {example.lower() == reconstructed.lower()}")
            
        except ValueError as e:
            print(f"Error: {e}")
    
    # Interactive mode
    print("\n" + "=" * 40)
    print("Interactive mode (enter 'quit' to exit):")
    
    while True:
        try:
            user_input = input("\nEnter U256 value (hex with 0x): ").strip()
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
                
            if not user_input:
                continue
                
            high_u128, low_u128 = u256_to_u128s(user_input)
            print(f"High U128:  {high_u128}")
            print(f"Low U128:   {low_u128}")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
