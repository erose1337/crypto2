import hashlib

import core
from parameters import PARAMETERS
from utilities import bytes_to_integer, random_integer_mod_q

def generate_private_key(parameters=PARAMETERS):
    r_size, q = parameters["r_size"], parameters['q']
    return [random_integer_mod_q(r_size, q) for count in range(parameters['n'])]

def generate_public_key(private_key, parameters=PARAMETERS):
    g, q, n = parameters["g"], parameters['q'], parameters['n']
    return [core.f(g, key_scalar, q, n) for key_scalar in private_key]

def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters)
    assert 0 not in public_key
    if len(public_key) > parameters['n']:
        raise SystemExit("Generated insecure public key")
    return public_key, private_key

def hash_to_scalar(m, parameters=PARAMETERS):
    q = parameters['q']
    h = getattr(hashlib, parameters["hash_algorithm"].lower())
    # WARNING: ensure h(m) is significantly larger than q to minimize bias
    return bytes_to_integer(bytearray(h(m).digest())) % q

def sign(private_key, m, parameters=PARAMETERS):
    s = stemp = hash_to_scalar(m, parameters)
    q = parameters['q']; n = parameters['n']
    pub2, priv2 = generate_keypair(parameters)
    preimage = [0] * n
    for i in range(n):
        x, y = private_key[i], priv2[i]
        xtemp, ytemp = x, y
        for j in range(n):
            preimage[j] = (preimage[j] + ((xtemp + ytemp) * stemp)) % q
            xtemp = (xtemp * x) % q
            ytemp = (ytemp * y) % q
        #key_vector = core.decompress_and_add(private_key[i], priv2[i], q, n)
        #preimage = core.add_vector(preimage,
        #                           core.scale_vector(key_vector, stemp, q),
        #                           q)
        stemp = (s * stemp) % q
    return preimage, pub2

def verify(public_key, m, signature, parameters=PARAMETERS):
    # add public_key and pub2
    # compute pub_r . S
    # verify preimage . G == pub_r . S
    n = parameters['n']; q = parameters['q']
    s = stemp = hash_to_scalar(m, parameters)
    preimage, pub2 = signature

    verifier = 0
    for i in range(n):
        # add public_key and pub2
        pub_r_i = (public_key[i] + pub2[i]) % q
        # pub_r . S (at index i)
        verifier = (verifier + (pub_r_i * stemp)) % q
        # s, ss, sss, ssss, ...
        stemp = (s * stemp) % q

    if core.dotproduct(parameters['G'], preimage) % q == verifier % q:
        return True
    else:
        return False

def test_sign_verify():
    import sys
    test_size = 1024
    print("Testing correctness of signatures...")
    for count in range(1, test_size + 1):
        public, private = generate_keypair()
        r = "unit test"
        signature = sign(private, r)
        assert verify(public, r, signature)

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

    import parameters
    N = parameters.N; q_size = parameters.PARAMETERS["q_size"]
    print("sign/verify test complete")
    private_size = q_size * len(private) * N
    compressed_size = q_size * len(private)
    public_size = q_size * len(public)
    sign_size = (q_size * N) + public_size
    messages = ["Time taken to produce {} signatures: {} seconds",
                "Time taken to verify  {} signatures: {} seconds",
                "Public key size : {} bits ({} bytes)",
                "Private key size: {} bits ({} bytes) (compressed)",
                "Private key size: {} bits ({} bytes) (uncompressed)",
                "Signature size  : {} bits ({} bytes)"]
    inserts = [(test_size, sign_time),
               (test_size, verify_time),
               (public_size, public_size / 8),
               (compressed_size, compressed_size / 8),
               (private_size, private_size / 8),
               (sign_size, sign_size / 8)]
    for message, inserts in zip(messages, inserts):
        print(message.format(*inserts))

if __name__ == "__main__":
    #test_serialize_deserialize()
    test_sign_verify()
