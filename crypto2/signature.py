import hashlib
import random
import ast # for literal_eval used in serialization

from utilities import (random_integer, random_vector, slide, psuedorandom_bytes,
                       bytes_to_integer)
from linearalgebra import dotproduct, mmul, add_vector, scale_vector
from function import *
from parameters import *

def generate_private_key(parameters=PARAMETERS):
    size = parameters["r_size"]; n = parameters['n']; q = parameters['q']
    private_key = []
    for count in range(n):
        scalar = random_integer(size)
        private_key.append(decompress(scalar, n, q))
    return private_key

def generate_public_key(private_key, parameters=PARAMETERS):
    g = parameters['G']; q = parameters['q']
    return [f(g, vector, q) for vector in private_key]

def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters)
    return public_key, private_key

def message_to_challenge(m, public_key, parameters=PARAMETERS):
    """ usage: message_to_challenge(message, parameters=PARAMETERS) => vector

        Deterministically map message to a vector suitable for use as a parameter to the `sign` function.
        message should be a sequence of bytes. """
    # m is of type `bytes` because most IO works on bytes rather than int
    public_key_bytes = serialize_public_key(public_key)
    # NOTE: public_key should be the real public key
    #       NOT the second public key
    #       NOT the randomized public key
    n = parameters['n']; k = parameters["security_level"]; q = parameters['q']
    h = getattr(hashlib, parameters["hash_algorithm"].lower())
    hash_input = m + public_key_bytes
    digest = bytearray(h(hash_input).digest())

    # generate enough random bytes to divide into n k-bit random integers
    # alternatively: Generate a scalar and decompress?
    bits_required = n * k; bytes_required, extra = divmod(bits_required, 8)
    if extra:
        bytes_required += 1
    _bytes = bytearray(psuedorandom_bytes(digest, '', bytes_required))
    vector = [bytes_to_integer(chunk) % q for chunk in slide(_bytes)]
    return vector

def sign(private_key, r, parameters=PARAMETERS):
    n = parameters['n']; q = parameters['q']
    pub2, priv2 = generate_keypair(parameters)
    priv_r = [add_vector(private_key[i], priv2[i], q) for i in range(n)]
    vector = [0] * n
    for i, scalar in enumerate(r):
        vector = add_vector(vector,
                            scale_vector(priv_r[i], scalar, q),
                            q)
    return vector, pub2

def decompress_and_sign(private_key, r, parameters=PARAMETERS):
    n = parameters['n']; q = parameters['q']
    pub2, priv2 = generate_keypair(parameters)
    priv_r = [add_vector(decompress(private_key[i], n=n),
                         priv2[i], q) for i in range(n)]
    vector = [0] * n
    for i, scalar in enumerate(r):
        vector = add_vector(vector,
                            scale_vector(priv_r[i], scalar, q),
                            q)
    return vector, pub2

def verify(public_key, r, signature, parameters=PARAMETERS):
    n = parameters['n']; g = parameters['G']; q = parameters['q']
    # there are other tests that should be done (e.g. ensure r is not low weight)
    #public_key, r, signature, n, g, q = sanitize_verify(public_key, r, signature, n, g, q)
    signing_vector, pub2 = signature
    pub_r = add_vector(public_key, pub2, q)
    verifier = f(pub_r, r, q)
    if f(signing_vector, g, q) == verifier:
        return True
    else:
        return False

def serialize_vector(vector):
    return bytes(vector)

def deserialize_vector(serialized_vector):
    return ast.literal_eval(serialized_vector)

def serialize_public_key(public_key):
    return serialize_vector(public_key)

def deserialize_public_key(serialized_public_key):
    return deserialize_vector(serialized_public_key)

def serialize_private_key(private_key, parameters=PARAMETERS):
    q = parameters['q']
    compressed = [compress(entry, q) for entry in private_key]
    return bytes(compressed)

def deserialize_private_key(serialized_priv, parameters=PARAMETERS):
    q = parameters['q']; n = parameters['n']
    return [decompress(item, n=n, q=q) for item in ast.literal_eval(serialized_priv)]

def serialize_signature(signature):
    return bytes(signature)

def deserialize_signature(serialized_signature):
    return ast.literal_eval(serialized_signature)

def test_serialize_deserialize():
    print("Testing signature.py serialization...")
    test_count = 1
    for count in range(test_count):
        public, private = generate_keypair()

        serialized_public = serialize_public_key(public)
        assert isinstance(serialized_public, bytes)
        _public = deserialize_public_key(serialized_public)
        assert _public == public

        serialized_private = serialize_private_key(private)
        assert isinstance(serialized_private, bytes)
        _private = deserialize_private_key(serialized_private)
        assert _private == private

        r = message_to_challenge("unit test", public)
        signature = sign(private, r)
        serialized_signature = serialize_signature(signature)
        assert isinstance(serialized_signature, bytes)
        _signature = deserialize_signature(serialized_signature)
        assert _signature == signature
    print("Serialization test complete")

def test_sign_verify():
    import sys
    test_size = 1024
    print("Testing correctness of signatures...")
    for count in range(1, test_size + 1):
        public, private = generate_keypair()
        compressed = [compress(key) for key in private]
        r = random_vector(N, Q, R_SIZE)
        signature = sign(private, r)
        assert verify(public, r, signature)

        r2 = random_vector(N, Q, R_SIZE)
        signature2 = decompress_and_sign(compressed, r2)
        assert verify(public, r2, signature2)
        sys.stdout.write('\b' * 79); sys.stdout.flush()
        progress = (100 * (count / float(test_size)), count, test_size)
        sys.stdout.write("{}% ({}/{})".format(*progress))
        sys.stdout.flush()

    print("\nTesting performance of signatures...")
    from timeit import default_timer as timestamp
    before = timestamp()
    for count in range(test_size):
        assert verify(public, r, signature)
    after = timestamp()
    verify_time = after - before

    before = timestamp()
    for count in range(test_size):
        sign(private, r)
    after = timestamp()
    sign_time = after - before

    from math import log, factorial
    print("sign/verify test complete")
    q_size = PARAMETERS["security_level"]
    public_size = q_size * N
    private_size = q_size * N * N
    comp_size = q_size * N
    sign_size = (q_size * N) + public_size
    print("Time taken to produce {} signatures: {} seconds".format(test_size, sign_time))
    print("Time taken to verify  {} signatures: {} seconds".format(test_size, verify_time))
    print("Public key size : {} bits ({} bytes)".format(public_size, public_size / 8))
    print("Private key size: {} bits ({} bytes) (uncompressed)".format(private_size, private_size / 8))
    print("Private key size: {} bits ({} bytes) (compressed)".format(comp_size, comp_size / 8))
    print("Signature size  : {} bits ({} bytes)".format(sign_size, sign_size / 8))

if __name__ == "__main__":
    test_serialize_deserialize()
    test_sign_verify()
