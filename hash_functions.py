# -*- coding: utf-8 -*-

def from_binary_to_hex(binary_num = ""):
    """
        Convert from binary to hex avoiding to lose 0's
        :binary_num: String, binary num like '0b0101' or '0101'
        :return: String, hex num like '0xff'
    """
    binary_num = binary_num.replace("0b", "")
    return "0x" + hex(int(binary_num, 2))[2:].zfill(int(len(binary_num)/4))

def a_xor_b(a = "", b = ""):
    """
        :a: String, binary num. e.g. '0100'
        :b: String, binary num. e.g. '1010'
        :return: String, binary xor result between a and b
    """
    x = int(a,2) ^ int(b,2)
    return '{0:0{1}b}'.format(x,len(a))

def hash_based_on_blocksystem(bloc_len = 4, m = "", initial_vector = ""):
    blocs = []
    i = 0
    while i < len(m):
        blocs.append(m[i:i+bloc_len])
        i += bloc_len
    
    vector = initial_vector
    for bloc in blocs:
        # g function: char[0]XORchar[1] char[1]XORchar[2]
        g = a_xor_b(vector[0], vector[1]) + a_xor_b(vector[2], vector[3])

        #bloc m XOR g[0]+g[1]+g[1]+g[0]        
        operation = a_xor_b(bloc, "%s%s"%(g[0:2], g[::-1]))
        
        #operation XOR vector
        vector = a_xor_b(operation, vector)
    
    return vector

def SHA256_ROTR(m = "", n_chars = 0):
    """
        Rotate n characters to the right, and fills the initial string with those ones.
    """
    message_rotated = m[-n_chars:] + m[:-n_chars]
    return message_rotated

def SHA256_SHR(m = "", n_chars = 0):
    """
        Shift n characters to the rights, and fills the initial string with zeros.
    """
    message_shifted = ("0"*n_chars) + m[:-n_chars]
    return message_shifted

def SHA256_block_expansion_sigma_calculator(hex_num = "", a_ROTR_num = 0, b_ROTR_num = 0, c_SHR_num = 0):
    """
        Calculate sigma σ from block expansion.
        :hex_num: String, hex number.
        :a_ROTR_num: int, sigma_0 => 7, sigma_1 => 17
        :b_ROTR_num: int, sigma_0 => 18, sigma_1 => 19
        :c_SHR_num: int, sigma_0 => 13, sigma_1 => 10
        :return: sigma
    """
    bin_num = bin(int(hex_num, 16)).replace("0b", "")
    a = SHA256_ROTR(bin_num, a_ROTR_num)
    b = SHA256_ROTR(bin_num, b_ROTR_num)
    c = SHA256_SHR(bin_num, c_SHR_num)
    sigma_bin = a_xor_b(a_xor_b(a, b), c)
    sigma_hex = from_binary_to_hex(sigma_bin)
    
    return sigma_hex
    
def SHA256_block_expansion_sigma_0(hex_num = ""):
    """
        :hex_num: String, hex number, without '0x' 1st chars.
        :return: String, hex number like '0xffc3ffe0'.
    """
    a_ROTR_num = 7
    b_ROTR_num = 18
    c_SHR_num = 3
    sigma_0 = SHA256_block_expansion_sigma_calculator(hex_num, a_ROTR_num, b_ROTR_num, c_SHR_num)
    
    return sigma_0

def SHA256_block_expansion_sigma_1(hex_num = ""):
    """
        :hex_num: String, hex number, without '0x' 1st chars.
        :return: String, hex number like '0xffc3ffe0'.
    """
    a_ROTR_num = 17
    b_ROTR_num = 19
    c_SHR_num = 10
    sigma_1 = SHA256_block_expansion_sigma_calculator(hex_num, a_ROTR_num, b_ROTR_num, c_SHR_num)
    
    return sigma_1

def SHA256_compression_function_sigma_calculator(hex_num = "", a_ROTR_num = 0, b_ROTR_num = 0, c_ROTR_num = 0):
    """
        Calculates sigma Σ from compression function.
        :hex_num: String, hex number.
        :a_ROTR_num: int, sigma_0 => 2, sigma_1 => 6
        :b_ROTR_num: int, sigma_0 => 13, sigma_1 => 11
        :c_ROTR_num: int, sigma_0 => 22, sigma_1 => 25
        :return: sigma
    """
    bin_num = bin(int(hex_num, 16)).replace("0b", "")
    a = SHA256_ROTR(bin_num, a_ROTR_num)
    b = SHA256_ROTR(bin_num, b_ROTR_num)
    c = SHA256_ROTR(bin_num, c_ROTR_num)
    sigma_bin = a_xor_b(a_xor_b(a, b), c)
    sigma_hex = from_binary_to_hex(sigma_bin)
    
    return sigma_hex

def SHA256_compression_function_sigma_0(hex_num = ""):
    """
        :hex_num: String, hex number, without '0x' 1st chars.
        :return: String, hex number like '0xffc3ffe0'.
    """
    a_ROTR_num = 2
    b_ROTR_num = 13
    c_ROTR_num = 22
    sigma_0 = SHA256_compression_function_sigma_calculator(hex_num, a_ROTR_num, b_ROTR_num, c_ROTR_num)
    
    return sigma_0

def SHA256_compression_function_sigma_1(hex_num = ""):
    """
        :hex_num: String, hex number, without '0x' 1st chars.
        :return: String, hex number like '0xffc3ffe0'.
    """
    a_ROTR_num = 6
    b_ROTR_num = 11
    c_ROTR_num = 25
    sigma_1 = SHA256_compression_function_sigma_calculator(hex_num, a_ROTR_num, b_ROTR_num, c_ROTR_num)
    
    return sigma_1

def SHA256_compression_function_Maj(a = "", b = "", c = ""):
    a_and_b = bin(int(a, 16) & int(b, 16))
    a_and_c = bin(int(a, 16) & int(c, 16))
    b_and_c = bin(int(b, 16) & int(c, 16))
    Maj_func = from_binary_to_hex(a_xor_b(a_xor_b(a_and_b, a_and_c), b_and_c))
    
    return Maj_func

def SHA256_compression_function_Ch(a = "", b = "", c = ""):
    a_and_b = bin(int(a, 16) & int(b, 16))
    negate_a_and_c = bin(~int(a, 16) & int(c, 16))
    Ch_func = from_binary_to_hex(a_xor_b(a_and_b, negate_a_and_c))
    
    return Ch_func
