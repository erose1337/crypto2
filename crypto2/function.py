from parameters import *
from linearalgebra import mmul, dotproduct
from utilities import random_vector, random_integer

def compress(vector, q=PARAMETERS['q']):
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

def decompress(scalar, n=PARAMETERS['n'], q=PARAMETERS['q']):
    return [pow(scalar, i, q) for i in range(1, n + 1)]

def f(a, v, q=PARAMETERS['q']):
    return dotproduct(a, v) % q

def test_f():
    from linearalgebra import scale_vector
    n = N
    for count in range(1024):
        a = random_vector(n, Q, R_SIZE)
        xs = random_integer(R_SIZE)
        xv = decompress(xs, n, Q)
        fx = f(a, xv)

        ys = random_integer(R_SIZE)
        yv = decompress(ys, n, Q)
        fy = f(a, yv)

        xyv = [(xv[i] + yv[i]) % Q for i in range(n)]
        fxy1 = f(a, xyv)
        fxy2 = (fx + fy) % Q
        assert fxy1 == fxy2

        s = random_integer(R_SIZE)
        assert (s * fx) % Q == f(a, scale_vector(xv, s, Q))

def test_compress_decompress():
    for count in range(1024):
        scalar = random_integer(R_SIZE) % Q
        vector = decompress(scalar, N, Q)
        _scalar = compress(vector)
        assert _scalar == scalar, (_scalar, scalar)

if __name__ == "__main__":
    test_f()
    test_compress_decompress()
