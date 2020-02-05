import random # used in primality testing
from os import urandom as random_bytes
import hmac
import hashlib
import itertools

def slide(iterable, x=16):
    """ Yields x entries at a time from iterable """
    slice_count, remainder = divmod(len(iterable), x)
    for position in range((slice_count + 1 if remainder else slice_count)):
        _position = position * x
        yield iterable[_position:_position + x]

def random_integer(size_in_bytes):
    return bytes_to_integer(bytearray(random_bytes(size_in_bytes)))

def random_integer_mod_q(size_in_bytes, q):
    return random_integer(size_in_bytes) % q

def random_coefficient(r_size, s_max):
    return random_integer_mod_q(r_size, s_max)

def random_vector(parameters):
    r_size = parameters["r_size"]; s_max = parameters["s_max"]
    return [random_coefficient(parameters) for i in range(parameters['n'])]

def compress(vector, q):
    degree = len(vector)
    elements = set(vector)
    assert len(elements) == len(vector), (len(elements), len(vector))
    for scalar in vector:
        for k in range(1, degree + 1):
            if pow(scalar, k, q) not in elements:
                break
        else:
            break
    else:
        raise ValueError("No relation found")
    return scalar

def decompress(scalar, n, q):
    return [pow(scalar, i, q) for i in range(1, n + 1)]

def compressible_vector(r_size, n, q):
    return decompress(random_integer(r_size), n, q)

def _hmac_rng(key, seed, hash_function="SHA256"):
    """ Generates psuedorandom bytes via HMAC. Implementation could be improved to
        a compliant scheme like HMAC-DRBG. """
    hasher = hmac.HMAC(key, seed, getattr(hashlib, hash_function.lower()))
    for counter in (str(number) for number in itertools.count()):
        yield hasher.digest()
        hasher.update(key + seed + counter)

def psuedorandom_bytes(key, seed, count, hash_function="SHA256"):
    """ usage: psuedorandom_bytes(key, seed, count,
                                  hash_function="SHA256") => psuedorandom bytes

        Generates count cryptographically secure psuedorandom bytes.
        Bytes are produced deterministically based on key and seed, using
        hash_function with _hmac_rng. """
    hash_function = hash_function.lower()
    generator = _hmac_rng(key, seed, hash_function)
    output = ''
    output_size = getattr(hashlib, hash_function)().digest_size
    iterations, extra = divmod(count, output_size)
    for round in range(iterations + 1 if extra else iterations):
        output += next(generator)
    return output[:count]

def bytes_to_integer(data):
    output = 0
    size = len(data)
    for index in range(size):
        output |= data[index] << (8 * (size - 1 - index))
    return output

def integer_to_bytes(integer, _bytes):
    output = bytearray()
    #_bytes /= 2
    for byte in range(_bytes):
        output.append((integer >> (8 * (_bytes - 1 - byte))) & 255)
    return output

def is_prime(n, _mrpt_num_trials=10): # from https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
    assert n >= 2
    # special case 2
    if n == 2:
        return True
    # ensure n is odd
    if n % 2 == 0:
        return False
    # write n-1 as 2**s * d
    # repeatedly try to divide n-1 by 2
    s = 0
    d = n-1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2**s * d == n-1)

    # test the base a to see whether it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite

    random.seed(random_bytes(32))
    for i in range(_mrpt_num_trials):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True # no base tested showed n as composite
