import ast

from parameters import *
from utilities import random_integer, random_vector
from linearalgebra import add_vector, scale_vector
from function import f, decompress

def generate_key_vector(r_size, n, q):
    s = random_integer(r_size)
    return decompress(s, n, q)

def generate_secret_key(parameters=PARAMETERS):
    r_size, q, n = parameters["r_size"], parameters['q'], parameters['n']
    prf_key = generate_key_vector(r_size, n, q)

    # WARNING: Ensure r_size is > q_size by a lot to minimize modulo bias
    # TODO: write a random_integer_mod_q function to do so automatically
    k = random_integer(r_size) % q
    return k, prf_key

def encrypt(key, m, parameters=PARAMETERS):
    # (k * f(x)) + m mod q
    n, q, r_size = parameters['n'], parameters['q'], parameters["r_size"]
    seed = random_vector(n, q, r_size)
    k, prf_key = key
    random_scalar = f(seed, prf_key, q=q)
    return seed, ((k * random_scalar) + m) % q

def decrypt(key, cryptogram, parameters=PARAMETERS):
    seed, ciphertext = cryptogram
    k, prf_key = key
    q = parameters['q']
    random_scalar = f(seed, prf_key, q=q)
    plaintext = (ciphertext - (k * random_scalar)) % q
    return plaintext

def add_ciphertexts(c1, c2, parameters=PARAMETERS):
    q = parameters['q']
    return (add_vector(c1[0], c2[0], q),
            (c1[1] + c2[1]) % q )

def scale_ciphertext(cryptogram, scalar, parameters=PARAMETERS):
    q = parameters['q']
    seed, ciphertext = cryptogram
    return scale_vector(seed, scalar, q), (scalar * ciphertext) % q

def serialize_key(key):
    return bytes(key)

def deserialize_key(key):
    return ast.literal_eval(key)

def serialize_ciphertext(ciphertext):
    return bytes(ciphertext)

def deserialize_ciphertext(serialized_ciphertext):
    return ast.literal_eval(serialized_ciphertext)

def test_serialize_deserialize():
    print("Testing encryption.py serialization...")
    key = generate_secret_key()
    serialized_key = serialize_key(key)
    _key = deserialize_key(serialized_key)
    assert _key == key

    ciphertext = encrypt(key, 0)
    serialized_ciphertext = serialize_ciphertext(ciphertext)
    _ciphertext = deserialize_ciphertext(serialized_ciphertext)
    assert _ciphertext == ciphertext
    print("Serialization test complete")

def test_encrypt_decrypt():
    test_count = 1024
    print("Testing correctness of encryption...")
    for test in range(test_count):
        message = 1
        key = generate_secret_key()
        ciphertext = encrypt(key, message)
        plaintext = decrypt(key, ciphertext)
        assert plaintext == message

        message2 = 2
        ciphertext2 = encrypt(key, message2)
        plaintext2 = decrypt(key, ciphertext2)
        assert plaintext2 == message2

        ciphertext3 = add_ciphertexts(ciphertext, ciphertext2)
        plaintext3 = decrypt(key, ciphertext3)
        assert plaintext3 == message + message2, (plaintext3, message + message2)

        r1 = random_integer(R_SIZE); r2 = random_integer(R_SIZE)
        cr1 = encrypt(key, r1); cr2 = encrypt(key, r2)
        cr3 = add_ciphertexts(cr1, cr2)
        pr4 = decrypt(key, cr3)
        assert pr4 == (r1 + r2) % Q, (pr4, (r1 + r2) % Q)

        random_scalar = random_integer(R_SIZE) % Q
        ciphertext = encrypt(key, 1)
        ciphertext2 = scale_ciphertext(ciphertext, random_scalar)
        plaintext2 = decrypt(key, ciphertext2)
        assert plaintext2 == random_scalar

    print("Testing performance of encryption...")
    from timeit import default_timer
    before = default_timer()
    for count in range(test_count):
        encrypt(key, message)
    after = default_timer()
    enc_time = after - before

    before = default_timer()
    for count in range(test_count):
        decrypt(key, ciphertext)
    after = default_timer()
    dec_time = after - before

    from math import log, factorial
    q_size = PARAMETERS["security_level"]
    key_size = q_size * N
    comp_size = q_size 
    c_size = q_size
    print("Time taken to encrypt: {} seconds".format(enc_time))
    print("Time taken to decrypt: {} seconds".format(dec_time))
    print("Key size: {} bits ({} bytes) (uncompressed)".format(key_size, key_size / 8))
    print("Key size: {} bits ({} bytes) (compressed)".format(comp_size, comp_size / 8))
    print("Ciphertext size: {} bits ({} bytes) (expansion factor: {})".format(c_size, c_size / 8, c_size / float(q_size)))

if __name__ == "__main__":
    test_serialize_deserialize()
    test_encrypt_decrypt()
