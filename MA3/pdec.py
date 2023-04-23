from cbc import bytes_to_bits, bits_to_bytes, cbc_dec, splitIntoBlocks, mergeBlocks, write_file, read_file
import sys
# If 1 byte needs to be added => the byte will have value 1.
# If no padding is required => two bytes will be added with value 16.
# Everything else => P bytes of value P.
# Should include some sort of indicator as to how many bytes that was padded in encryption/decryption.
# Running the program in CLI like this: python penc plaintext key iv output file.
# The files with "pad" at the beginning is the sample data.

""" Task 2 - Block cipher with padding in CBC mode of operation - decryption part"""
def main():
    file_in = sys.argv[1]
    input_data_bytes = read_file(f"{file_in}")
    # convert data of the input file into bits:
    input_data_bits = bytes_to_bits(input_data_bytes)
    # Key
    key_file = sys.argv[2]
    key = read_file(f"{key_file}")
    key = bytes_to_bits(key)
    # IV
    initial_vector_file = sys.argv[3]
    initial_vector = read_file(f"{initial_vector_file}")
    initial_vector = bytes_to_bits(initial_vector)

    output_file = sys.argv[4]

    plaintext_blocks = padded_decryption(input_data_bits, initial_vector, key)
    plaintext = mergeBlocks(plaintext_blocks)
    write_file(output_file, bits_to_bytes(plaintext))

    sample_plaintext = bytes_to_bits(read_file("pad_in"))

    # Need to convert to sets to be able to compare the content of lists.
    print(set(plaintext) == set(sample_plaintext))

def padded_decryption(input_bits: list, initial_vector: list, key: list) -> list:
    input_length: int = len(input_bits)

    if input_length % 16 == 0:  # No padding is needed, but we append to bytes of value 16 each.
        padding_bytes = [0, 0, 0, 1, 0, 0, 0, 0] + [0, 0, 0, 1, 0, 0, 0, 0]
    else:  # one byte is needed to be padded, 1 byte of value 1.
        padding_bytes = [0, 0, 0, 0, 0, 0, 0, 1]  # 8 bits = 1 byte.

    input_bits.extend(padding_bytes)
    input_blocks = splitIntoBlocks(input_bits, 16)

    return cbc_dec(input_blocks, initial_vector, key)


if __name__=="__main__":
    main()