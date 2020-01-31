import ast

import encryption
from parameters import PARAMETERS
from utilities import random_integer
from function import decompress
from linearalgebra import add_vector, scale_vector

def generate_private_key(parameters=PARAMETERS):
    return encryption.generate_secret_key(parameters)

def generate_public_key(private_key, parameters=PARAMETERS):
    # WARNING: Do not output more than n points or the key will leak
    encrypt = encryption.encrypt
    return [encrypt(private_key, 1)] + [encrypt(private_key, 0) for count in
                                        range(parameters['n'] - 1)]

def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters)
    if len(public_key) > parameters['n']:
        raise SystemExit("Generated insecure keypair")
    return public_key, private_key

def encapsulate_secret(public_key, parameters=PARAMETERS):
    q, r_size, n = parameters['q'], parameters["r_size"], parameters['n']
    s = random_integer(r_size)
    secret_vector = decompress(s, n, q)
    output_seed = [0] * n
    output = 0
    for i, entry in enumerate(public_key):
        scalar = secret_vector[i]
        key_vector, key_scalar = entry
        output_seed = add_vector(output_seed, scale_vector(key_vector, scalar, q), q)
        output = (output + (key_scalar * scalar)) % q
    return secret_vector[0], (output_seed, output)

def recover_secret(private_key, encapsulated_secret, parameters=PARAMETERS):
    return encryption.decrypt(private_key, encapsulated_secret, parameters)

def serialize_private_key(private_key):
    return encryption.serialize_key(private_key)

def deserialize_private_key(serialized_key):
    return encryption.deserialize_key(serialized_key)

def serialize_public_key(public_key):
    return bytes(public_key)

def deserialize_public_key(serialized_key):
    return ast.literal_eval(serialized_key)

def serialize_cryptogram(encapsulated_secret):
    return bytes(encapsulated_secret)

def deserialize_cryptogram(serialized_cryptogram):
    return ast.literal_eval(serialized_cryptogram)

def test_serialize_deserialize():
    print("Testing kem.py serialization...")
    public, private = generate_keypair()

    serialized_public = serialize_public_key(public)
    _public = deserialize_public_key(serialized_public)
    assert _public == public

    serialized_private = serialize_private_key(private)
    _private = deserialize_private_key(serialized_private)
    assert _private == private

    share, cryptogram = encapsulate_secret(public)
    serialized_cryptogram = serialize_cryptogram(cryptogram)
    _cryptogram = deserialize_cryptogram(serialized_cryptogram)
    assert _cryptogram == cryptogram

    print("Serialization test complete")

def test_kem():
    test_size = 1024
    print("Testing correctness of KEM...")
    for count in range(test_size):
        public, private = generate_keypair()
        secret, encapsulated = encapsulate_secret(public)
        _secret = recover_secret(private, encapsulated)
        assert _secret == secret

    print("Testing performance of KEM...")
    from timeit import default_timer
    before = default_timer()
    for count in range(test_size):
        encapsulate_secret(public)
    after = default_timer()
    encaps_time = after - before

    before = default_timer()
    for count in range(test_size):
        recover_secret(private, encapsulated)
    after = default_timer()
    recover_time = after - before

    q_size = PARAMETERS["security_level"]; n = PARAMETERS['n']
    pub_size = q_size * n
    priv_size = q_size + (q_size * n)
    comp_size = q_size + q_size
    print("Time taken to encapsulate {} keys: {} seconds".format(test_size, encaps_time))
    print("Taken taken to recover    {} keys: {} seconds".format(test_size, recover_time))
    print("Public key size : {} bits ({} bytes)".format(pub_size, pub_size / 8))
    print("Private key size: {} bits ({} bytes) (uncompressed)".format(priv_size, priv_size / 8))
    print("Private key size: {} bits ({} bytes) (compressed)".format(comp_size, comp_size / 8))
    print("Cryptogram size : {} bits ({} bytes)".format(q_size, q_size / 8))

if __name__ == "__main__":
    test_serialize_deserialize()
    test_kem()
