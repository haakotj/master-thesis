import math
import struct

############################ CHACHA20

def rotate_left(val, numb):
    return ((val << numb) & 0xffffffff) | val >> (32 - numb)


def Quarter_round(state,a,b,c,d):
    state[a] = (state[a] + state[b]) & 0xffffffff; state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xffffffff; state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xffffffff; state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xffffffff; state[b] = rotate_left(state[b] ^ state[c], 7)

def inner_block(state):
    Quarter_round(state, 0, 4, 8, 12)
    Quarter_round(state, 1, 5, 9, 13)
    Quarter_round(state, 2, 6, 10, 14)
    Quarter_round(state, 3, 7, 11, 15)
    Quarter_round(state, 0, 5, 10, 15)
    Quarter_round(state, 1, 6, 11, 12)
    Quarter_round(state, 2, 7, 8, 13)
    Quarter_round(state, 3, 4, 9, 14)
    return state    


def chacha20_block(key, counter, nonce):
    constant_word = b'expand 32-byte k'
    constants = [val for val in struct.unpack('<IIII', constant_word)]
    key = [val for val in struct.unpack('<IIIIIIII', key)]
    counter = [counter]
    nonce = [val for val in struct.unpack('<III', nonce)]

    #state = constants | key | counter | nonce
    state = constants + key + counter + nonce
    initial_state = state

    #20 rounds (10 iterations of the list)
    for i in range(0,10):
        state = inner_block(state)

    #state += initial_state: 
    for i in range(0,len(state)): 
        state[i] = (state[i] + initial_state[i]) & 0xffffffff

    #Serialize:
    return serialize(state)

def serialize(state):
    little_endian_order = [struct.pack('<I', int(val)) for val in state]
    keystream_block = b''.join(little_endian_order)
    return keystream_block

def chacha20_encrypt(key, counter, nonce, plaintext):
    encrypted_message = b''
    for j in range(0,math.floor(len(plaintext) / 64)):
        key_stream = chacha20_block(key, counter+j, nonce)
        #64 byte blocks:
        block = plaintext[j*64 : (j+1)*64]
        
        #XOR-ing keystream with plaintext:
        zipped = zip(block, key_stream)
        encrypted_message += bytes(block ^ key_stream for block, key_stream in zipped)

    if (len(plaintext) % 64) != 0:
        j = math.floor(len(plaintext) / 64)
        key_stream = chacha20_block(key, counter+j, nonce)
        block = plaintext[j*64 : len(plaintext)]

        #XOR-ing keystream with plaintext:
        zipped = zip(block, key_stream)
        encrypted_message += bytes(block ^ key_stream for block, key_stream in zipped)

    return encrypted_message


############################ POLY1305

#Convert a number from little endian byte format:
def convert_little_endian_bytes_to_number(little_endian_byte): 
    return int.from_bytes(little_endian_byte, byteorder = 'little')

#Convert number to 8 bytes in little endian format:
def convert_to_8_bytes_little_endian(num):
    le_8 = num.to_bytes(8,byteorder='little')
    return bytearray(le_8) 

#Convert number to 16 bytes in little endian format:
def convert_to_16_bytes_little_endian(num):
    le = num.to_bytes(32,byteorder='little')
    le_16 = le[:16]
    return bytearray(le_16)

def poly1305_mac(msg, key):
    K_r = convert_little_endian_bytes_to_number(key[0:16])
    #K_r is clamped:
    K_r = K_r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    K_s = convert_little_endian_bytes_to_number(key[16:32])
    accumulator = 0 
    #Set p to 2^130-5:
    p = 0x3fffffffffffffffffffffffffffffffb
    for i in range(1, math.ceil(len(msg)/16)):
        n = convert_little_endian_bytes_to_number(msg[(i-1)*16 : i*16] + b'\x01')
        accumulator += n
        accumulator = (K_r * accumulator) % p
    accumulator += K_s
    return convert_to_16_bytes_little_endian(accumulator)

############################ CHACHA20-POLY1305:

def poly1305_key_generation(key, nonce):
    ctr = 0
    block = chacha20_block(key, ctr, nonce)
    return block[0:32]

def pad16(x):
    if len(x) % 16 == 0: 
        return None
    else:
        num_pad_bytes = 16 - (len(x) % 16)
        return num_pad_bytes*b'\x00'

def concatenate_mac_data(ad, ciphertext):
    mac_data = ad + pad16(ad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += convert_to_8_bytes_little_endian(len(ad))
    mac_data += convert_to_8_bytes_little_endian(len(ciphertext))
    return mac_data 

def chacha20_aead_encrypt(ad, k_m, k_c, nonce, plaintext):
    #if the nonce is not 96 bits, it should be concatenating with a constant to become 96 bits
    #This code assume the nonce is 96 bits as specified in RFC8439 
    one_time_key = poly1305_key_generation(k_m, nonce)
    ciphertext = chacha20_encrypt(k_c, 1, nonce, plaintext)
    mac_data = concatenate_mac_data(ad, ciphertext)
    tag = poly1305_mac(mac_data, one_time_key)
    return (ciphertext, tag)


def chacha20_aead_decrypt(ad, k_m, k_c, nonce, ciphertext):
    one_time_key = poly1305_key_generation(k_m, nonce)
    plaintext = chacha20_encrypt(k_c, 1, nonce, ciphertext)
    mac_data = concatenate_mac_data(ad, ciphertext)
    tag = poly1305_mac(mac_data, one_time_key)
    return (plaintext, tag)


def poly1305_verify_message(ad, k_m, nonce, ciphertext):
    one_time_key = poly1305_key_generation(k_m, nonce)
    mac_data = concatenate_mac_data(ad, ciphertext)
    tag = poly1305_mac(mac_data, one_time_key)
    return tag

def compare_mac(a, b):
    if len(a) == len(b):
        if a == b:
            return True
    else:
        return False


#Encrypting the ciphertext and generating the authentication-tag
def chaCha20_poly1305_authenticated_encryption(k_m, k_c, nonce, plaintext, ad):
    return chacha20_aead_encrypt(k_m = k_m, k_c = k_c, nonce=nonce, plaintext=plaintext, ad=ad)

#Verify the authentication-tag without decrypting the ciphertext
def chaCha20_poly1305_authenticate_only(k_m, nonce, ciphertext, mac, ad):
    tag = poly1305_verify_message(k_m=k_m, nonce=nonce, ciphertext=ciphertext, ad=ad)
    return compare_mac(tag, mac)

#Verify the authentication-tag and decrypting the ciphertext
def chaCha20_poly1305_authenticated_decryption(k_m, k_c, nonce, ciphertext, mac, ad):
    plaintext, tag = chacha20_aead_decrypt(k_m = k_m, k_c = k_c, nonce=nonce, ciphertext=ciphertext, ad=ad)
    if compare_mac(tag, mac):
        print("Message verified! Plaintext is:")
        print(plaintext.decode('utf-8'))
    else:
        print("Message not verified. Message discarded")
        return False

