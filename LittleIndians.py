def string_to_little_endian_push(input_string):
    # Ensure length is multiple of 4 by padding with null bytes
    padding_len = (4 - len(input_string) % 4) % 4
    padded = input_string + "\x00" * padding_len

    # Split into chunks of 4 bytes
    chunks = [padded[i:i+4] for i in range(0, len(padded), 4)]

    # Generate push instructions in reverse order
    result = []
    for chunk in reversed(chunks):
        # Convert each chunk to hex in little endian order
        hex_val = ''.join(f'{ord(c):02x}' for c in reversed(chunk))
        result.append(f' "   push  0x{hex_val}                ;"' + f" # '{chunk}'")

    return '\n'.join(result)

# Example usage:
your_string = r'TEXT OR PATH HERE'
print(string_to_little_endian_push(your_string))
