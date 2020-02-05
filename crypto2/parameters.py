from utilities import is_prime, compressible_vector

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
    print("Warning: secure parameterization for 'n' not established")

    # picks the largest n that will allow a signature to fit in 1 packet
    budget = 1500 * 8        # MTU, amount of space available in a single packet
    q_size = (security_level * 2)
    n = int(float(budget / 2) / q_size)
    q = generate_q(q_size)
    print("Using log2(q)=2^{}, n={} for k={}".format(q_size, n, security_level))

    r_size = q_size + security_level    # in bytes; larger than q to reduce bias
    s_max = 2 ** security_level
    hash_algorithm = "SHA512"
    G = compressible_vector(r_size, n, q)
    g = G[0]
    parameters = {"security_level" : 128, 'q' : q, 'n' : n, 'G' : G, 'g' : g,
                  "r_size" : r_size, "s_max" : s_max, "q_size" : q_size,
                  "hash_algorithm" : hash_algorithm}
    return q, n, r_size, s_max, G, parameters

Q, N, R_SIZE, S_MAX, G, PARAMETERS = generate_parameters(128)
