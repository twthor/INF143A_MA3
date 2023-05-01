from cbc import bytes_to_bits, bits_to_bytes, cbc_dec, splitIntoBlocks, mergeBlocks, write_file, read_file
import sys
# If 1 byte needs to be added => the byte will have value 1.
# If no padding is required => two bytes will be added with a total value of 16.
# Should include some sort of indicator as to how many bytes that was padded in encryption/decryption.
# Running the program in CLI like this: python pdec.py plaintext key iv output file.
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

    plaintext = padded_decryption(input_data_bits, initial_vector, key)
    write_file(output_file, bits_to_bytes(plaintext))

    sample_plaintext = bytes_to_bits(read_file("pad_in"))

    print(plaintext == sample_plaintext)

def padded_decryption(input_bits: list, initial_vector: list, key: list) -> list:
    input_blocks = splitIntoBlocks(input_bits, 16)
    plaintext = cbc_dec(input_blocks, initial_vector, key)
    plaintext = mergeBlocks(plaintext)

    # The thing about decrypting in regard to padding, is that when we padded with bytes of certain value during
    # encryption, we need to check the values of the last bytes to see if we either padded with 2 bytes or 1 byte.
    # We can then know how many bytes to remove from the decrypted material.
    if plaintext[-16:] == [0, 0, 0, 0, 0, 0, 0, 0] + [0, 0, 0, 1, 0, 0, 0, 0]:  # split into two lists to make it easier to read the byte values.
        plaintext = plaintext[:len(plaintext)-16] # 2 bytes = 16 bits
    elif plaintext[-8:] == [0, 0, 0, 0, 0, 0, 0, 1]:  # one byte from padding is removed. 1 byte = 8 bits
        plaintext = plaintext[:len(plaintext)-8]

    return plaintext


if __name__=="__main__":
    main()