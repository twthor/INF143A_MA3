from cbc import bytes_to_bits, bits_to_bytes, cbc_enc, splitIntoBlocks, \
    mergeBlocks, write_file, read_file
import sys
# If 1 byte needs to be added => the byte will have value 1.
# If no padding is required => two bytes will be added with value 16.
# Everything else => P bytes of value P.
# Should include some sort of indicator as to how many bytes that was padded in encryption/decryption.
# Running the program in CLI like this: python penc plaintext key iv output file.

""" Task 2 - Block cipher with padding in CBC mode of operation - encryption part"""
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

    ciphertext_blocks = padded_encryption(input_data_bits, initial_vector, key)

    sample_ciphertext = bytes_to_bits(read_file("pad_out"))

    ciphertext = mergeBlocks(ciphertext_blocks)
    write_file(output_file, bits_to_bytes(ciphertext))

    # Just a test to see if encryption is correct
    # Need to convert to sets to be able to compare the content of lists.
    print(set(ciphertext)==set(sample_ciphertext))

# The one thing I only need to think about is the padding part and how to solve that. The CBC encryption from CBC.py
# should do the rest.
def padded_encryption(input_bits: list, initial_vector: list, key: list) -> list:
    input_length: int = len(input_bits)

    if input_length % 16 == 0:  # No padding is needed, but we append to bytes of value 16 each.
        padding_bytes = [0, 0, 0, 1, 0, 0, 0, 0] + [0, 0, 0, 1, 0, 0, 0, 0]
    else:  # one byte is needed to be padded, 1 byte of value 1.
        padding_bytes = [0, 0, 0, 0, 0, 0, 0, 1]  # 8 bits = 1 byte.

    input_bits.extend(padding_bytes)
    input_blocks = splitIntoBlocks(input_bits, 16)

    return cbc_enc(input_blocks, initial_vector, key)


if __name__=="__main__":
    main()
