from utilities import random_vector, is_prime

__all__ = ['Q', 'N', "R_SIZE", 'G', "PARAMETERS"]

def find_closest_prime(n):
    if n % 2:
        offset = 0
    else:
        offset = 1
    while not is_prime(n + offset):
        offset += 2
    return offset

def generate_q(q_size):
    q_start = 2 ** q_size
    offset = find_closest_prime(q_start)
    return q_start + offset

def generate_parameters(security_level):
    print("Warning: parameterization fixed at 128-bit")
    print("Warning: secure parameters not established")
    # TODO: generate parameters for the specified security level
    assert security_level == 128
    q = generate_q(security_level)
    q_size = 128
    n = 16
    r_size = 64 # in bytes; larger than q to reduce bias
    G = random_vector(n, q, r_size)
    hash_algorithm = "SHA256"
    parameters = {'q' : q, 'n' : n, "r_size" : r_size, 'G' : G,
                  "security_level" : 128, "hash_algorithm" : hash_algorithm}
    return q, n, r_size, G, parameters

Q, N, R_SIZE, G, PARAMETERS = generate_parameters(128)
