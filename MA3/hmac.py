from cipher import read_file, write_file, bytes_to_bits, bits_to_bytes, XOR
from hashlib import sha256
from cbc import splitIntoBlocks, mergeBlocks
import sys
# Run as: python hmac.py file_in key output_file

def compute_hmac(file, key):
    inner_pad_pattern = [0, 0, 1, 1, 0, 1, 1, 0]
    outer_pad_pattern = [0, 1, 0, 1, 1, 1, 0, 0]

    # Don't need to pad the key? Arne said the key is expected to be the same size as the block size.
    # And in the lecture, Nikolay said we can drop the EXP-part if that's the case.
    inner_pad = inner_pad_pattern * int(len(key)/len(inner_pad_pattern))
    outer_pad = outer_pad_pattern * int(len(key)/len(outer_pad_pattern))

    key_xor_innerpad = XOR(key, inner_pad) # S_i
    key_innerpad_file = key_xor_innerpad + file # concatenated before hashing

    hash_input = b"".join(bits_to_bytes(key_innerpad_file)) # the sha256 function needs input to be of type bytes.
    tmp_hash = sha256(hash_input)

    key_xor_outpad = XOR(key, outer_pad) # S_o
    hash_bytes = bytes.fromhex(tmp_hash.hexdigest()) # converts from hexadecimal to bytes
    hash_in_bits = bytes_to_bits(hash_bytes) # converts from list of bytes to bits.

    outerpad_tmphash = key_xor_outpad + hash_in_bits # S_o + tmp_hash

    second_hash_input = b"".join(bits_to_bytes(outerpad_tmphash)) # joins the list of bytes to a string prepare it
    # as input for the sha256() function as it requires a string of bytes.

    hmac = sha256(second_hash_input) # No IV input needed for Sha256.
    hmac = bytes.fromhex(hmac.hexdigest()) # convert the hash in hexadecimal to bytes
    hmac = bytes_to_bits(hmac) # formatting it, so it works with the write_file() function from cipher.py
    return bits_to_bytes(hmac)


def main():
    file_in = sys.argv[1]
    file_in = read_file(file_in)
    file = bytes_to_bits(file_in)

    key_file = sys.argv[2]
    key_file = read_file(key_file)
    key = bytes_to_bits(key_file)

    output_file = sys.argv[3]

    # shat256()
    hmac = compute_hmac(file, key)
    write_file(output_file, hmac)

    sample_hmac = read_file("hash_out")
    # print(sample_hmac, " from sample data")
    hmac_test = b"".join(hmac) # join the list of bytes to be able to compare the hashes
    # print(hmac_test, " formatted from list of bytes to byte-string")
    print(hmac_test == sample_hmac)

if __name__ == "__main__":
    main()