import ast

from parameters import *
from utilities import random_integer_mod_q
import core

def f(X, y, q, n):
    # operates on uncompressed vector X and compressed scalar y
    output = 0
    ytemp = y
    assert isinstance(X, list), type(X)
    for i, scalar in enumerate(X):
        output = (output + (ytemp * scalar)) % q
        ytemp = (ytemp * y) % q
    return output

def decompress(x, q, n):
    return [pow(x, i, q) for i in range(1, n + 1)]
    #xtemp = 1
    #for i in range(1, n + 1):
    #    xtemp = (xtemp * x) % q
    #    yield xtemp

def generate_secret_key(parameters=PARAMETERS):
    r_size, q, n = parameters["r_size"], parameters['q'], parameters['n']
    prf_key = random_integer_mod_q(r_size, q)#compressible_vector(r_size, n, q)
    k = random_integer_mod_q(r_size, q)
    return k, prf_key

def encrypt(key, m, parameters=PARAMETERS):
    # (k * f(x)) + m mod q
    n, q, r_size = parameters['n'], parameters['q'], parameters["r_size"]
    seed = random_integer_mod_q(r_size, q)#compressible_vector(r_size, n, q)
    k, prf_key = key
    random_scalar = core.f(seed, prf_key, q, n)
    output = seed, ((k * random_scalar) + m) % q
    #test = ([pow(seed, i, q) for i in range(1, n + 1)], output[1])
    #assert decrypt(key, test, parameters) == m
    return output

def decrypt(key, cryptogram, parameters=PARAMETERS):
    seed, ciphertext = cryptogram
    k, prf_key = key
    q = parameters['q']
    random_scalar = f(seed, prf_key, q, parameters['q'])
    plaintext = (ciphertext - (k * random_scalar)) % q
    return plaintext

def add_ciphertexts(c1, c2, parameters=PARAMETERS):
    q, n = parameters['q'], parameters['n']
    assert isinstance(c1, list) or isinstance(c1, tuple), type(c1)
    assert isinstance(c2, list) or isinstance(c2, tuple), type(c2)
    seed1 = c1[0]; seed2 = c2[0];
    #assert isinstance(seed1, int), type(seed1)
    #assert isinstance(seed2, int), type(seed2)
    seed3 = core.decompress_and_add(seed1, seed2, q, n)
    return (seed3, (c1[1] + c2[1]) % q)

def add_scaled_ciphertexts(c1, c2, parameters=PARAMETERS):
    q, n = parameters['q'], parameters['n']
    assert isinstance(c1, list) or isinstance(c1, tuple), type(c1)
    assert isinstance(c2, list) or isinstance(c2, tuple), type(c2)
    seed1 = c1[0]; seed2 = c2[0];
    #assert isinstance(seed1, int), type(seed1)
    #assert isinstance(seed2, int), type(seed2)
    seed3 = core.add_vector(seed1, seed2, q)
    return (seed3, (c1[1] + c2[1]) % q)

def scale_ciphertext(cryptogram, scalar, parameters=PARAMETERS):
    q = parameters['q']; n = parameters['n']
    seed, ciphertext = cryptogram
    seed_out = []
    seed_temp = seed
    for i in range(1, n): # do last append after loop to avoid doing extra work
        seed_out.append((scalar * seed_temp) % q)
        seed_temp = (seed_temp * seed) % q
    seed_out.append((scalar * seed_temp) % q)
    return seed_out, (scalar * ciphertext) % q

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
        ciphertext = (decompress(ciphertext[0], Q, N), ciphertext[1])
        plaintext = decrypt(key, ciphertext)
        assert plaintext == message

        message2 = 2
        ciphertext2 = encrypt(key, message2)
        ciphertext2 = (decompress(ciphertext2[0], Q, N), ciphertext2[1])
        plaintext2 = decrypt(key, ciphertext2)
        assert plaintext2 == message2

        ciphertext = encrypt(key, 1); ciphertext2 = encrypt(key, 2)
        ciphertext3 = add_ciphertexts(ciphertext, ciphertext2)
        plaintext3 = decrypt(key, ciphertext3)
        assert plaintext3 == message + message2, (plaintext3, message + message2)

        r1 = random_integer_mod_q(R_SIZE, Q)
        r2 = random_integer_mod_q(R_SIZE, Q)
        cr1 = encrypt(key, r1); cr2 = encrypt(key, r2)
        cr3 = add_ciphertexts(cr1, cr2)
        pr4 = decrypt(key, cr3)
        assert pr4 == (r1 + r2) % Q, (pr4, (r1 + r2) % Q)

        random_scalar = random_integer_mod_q(R_SIZE, Q)
        ciphertext_of_1 = encrypt(key, 1)
        ciphertext_of_r = scale_ciphertext(ciphertext_of_1, random_scalar)
        plaintext_r = decrypt(key, ciphertext_of_r)
        assert plaintext_r == random_scalar

        random_scalar2 = random_integer_mod_q(R_SIZE, Q)
        ciphertext_of_0 = encrypt(key, 0)
        ciphertext_of_02 = scale_ciphertext(ciphertext_of_0, random_scalar2)

        ciphertext_of_r_02 = add_scaled_ciphertexts(ciphertext_of_r,
                                                    ciphertext_of_02)
        plaintext_r_02 = decrypt(key, ciphertext_of_r_02)
        assert plaintext_r_02 == plaintext_r == random_scalar

    print("Testing performance of encryption...")
    from timeit import default_timer
    before = default_timer()
    for count in range(test_count):
        encrypt(key, message)
    after = default_timer()
    enc_time = after - before

    ciphertext = (decompress(ciphertext[0], Q, N), ciphertext[1])
    before = default_timer()
    for count in range(test_count):
        decrypt(key, ciphertext)
    after = default_timer()
    dec_time = after - before


    q_size = PARAMETERS["security_level"]; n = PARAMETERS['n']
    key_size = q_size + q_size
    uncompressed_key_size = q_size + (q_size * n)
    cryptogram1 = q_size + q_size
    cryptogram2 = q_size + (q_size * n)

    messages = ("Time taken to encrypt {} messages: {} seconds",
                "Time taken to decrypt {} messages: {} seconds",
                "Key size: {} bits ({} bytes) (compressed)",
                "Key size: {} bits ({} bytes) (uncompressed)",
                "Ciphertext (fresh) size: {} bits ({} bytes) (expansion: {})",
                "Ciphertext (added) size: {} bits ({} bytes) (expansion: {})")
    inserts = ((test_count, enc_time),        # using tuples makes the * below work nicely
               (test_count, dec_time),
               (key_size, key_size / 8),
               (uncompressed_key_size, uncompressed_key_size / 8),
               (cryptogram1, cryptogram1 / 8, float(cryptogram1) / q_size),
               (cryptogram2, cryptogram2 / 8, float(cryptogram2) / q_size))
    for message, insert in zip(messages, inserts):
        print(message.format(*insert))

if __name__ == "__main__":
    test_serialize_deserialize()
    test_encrypt_decrypt()
