from random import randbytes

from .challenge9 import add_pkcs7_padding
from .challenge10 import encrypt_aes_128_ecb
from .challenge11 import ecb_detector


def ecb_encryption_oracle_hard(key, prefix, user_data, hidden_message):
    padded_plaintext = add_pkcs7_padding(prefix + user_data + hidden_message, 16)
    return encrypt_aes_128_ecb(key, padded_plaintext)


def get_repeated_blocks(ciphertext: bytes, block_size: int) -> dict:
    block_positions = {}
    i = 0
    while i * 16 <= len(ciphertext):
        block = ciphertext[block_size * (i - 1) : block_size * i]
        if block in block_positions:
            block_positions[block].append(i)
        else:
            block_positions[block] = [i]
        i += 1
    repeated_positions = {}
    for k, v in block_positions.items():
        if len(v) > 1:
            repeated_positions[k] = v
    return repeated_positions


def decrypt_unknown_string_hard(ciphertext_getter):
    # Determine block size
    buffer = b""
    no_input_ciphertext = ciphertext_getter(buffer)
    while (ciphertext_len := len(ciphertext_getter(buffer))) == len(
        no_input_ciphertext
    ):
        buffer += b"a"
    block_size = ciphertext_len - len(no_input_ciphertext)

    # Determine ECB
    ciphertext = ciphertext_getter(b"a" * block_size * 3)
    is_ecb = ecb_detector(ciphertext)

    # Identify prefix length
    no_input_repeated_blocks = get_repeated_blocks(no_input_ciphertext, block_size)
    no_input_repeated_blocks_set = set(no_input_repeated_blocks.keys())
    while (test_block := randbytes(block_size)) in no_input_repeated_blocks_set:
        # Making sure that the test block is not already present in prefix
        continue
    padding = 0
    while True:
        forged_buffer = b"a" * padding + test_block * 2
        forged_ciphertext = ciphertext_getter(forged_buffer)
        repeated_blocks = get_repeated_blocks(forged_ciphertext, block_size)
        if len(repeated_blocks) > len(no_input_repeated_blocks):
            break
        else:
            padding += 1
    new_set_of_repeated_blocks = set(repeated_blocks.keys())
    added_blocks = next(iter(new_set_of_repeated_blocks - no_input_repeated_blocks_set))
    added_block_position = min(repeated_blocks[added_blocks])
    initial_prefix_len = block_size * (added_block_position - 1) - padding
    hidden_message_len = (
        len(forged_ciphertext) - 2 * block_size - initial_prefix_len - padding
    )

    # Decrypt target message
    hidden_message = b""
    for idx in range(hidden_message_len):
        count_of_previous_blocks = idx // block_size
        block_start = (
            block_size * (added_block_position - 1)
            + count_of_previous_blocks * block_size
        )
        block_end = (
            block_size * (added_block_position - 1)
            + (count_of_previous_blocks + 1) * block_size
        )
        buffer = b"a" * (padding + block_size - idx % block_size - 1)
        target = ciphertext_getter(buffer)[block_start:block_end]
        next_plaintext_byte = None
        for x in range(256):
            c = bytes([x])
            test_buffer = buffer + hidden_message + c
            test_ciphertext = ciphertext_getter(test_buffer)[block_start:block_end]
            if target == test_ciphertext:
                next_plaintext_byte = c
                break
        if next_plaintext_byte:
            hidden_message += next_plaintext_byte
            continue
        else:
            break
    if hidden_message[-1] == 1:
        # delete first decoded padding
        hidden_message = hidden_message[:-1]
    return block_size, is_ecb, initial_prefix_len, hidden_message
