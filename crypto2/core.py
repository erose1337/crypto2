def dotproduct(v1, v2):
    return sum(v1[i] * v2i for i, v2i in enumerate(v2))

def scale_vector(v, s, q):
    return [(x * s) % q for x in v]

def add_vector(v1, v2, q):
    #print v1
    #print [(i, scalar) for i, scalar in enumerate(v2)]
    #for i, scalar in enumerate(v2):
    #    print i, scalar
    #    yield (v1[i] + scalar) % q
    return [(v1[i] + v2i) % q for i, v2i in enumerate(v2)]

def decompress_and_add(x, y, q, n):
    # [(pow(x, i, q) + pow(y, i, q)) % q for i in range(1, n + 1)]
    output = []
    xtemp = x; ytemp = y
    for i in range(1, n + 1):
        #yield (xtemp + ytemp) % q
        output.append((xtemp + ytemp) % q)
        xtemp = (xtemp * x) % q; ytemp = (ytemp * y) % q
    return output

def f(x, y, q, n):
    # decompress two scalars `x, y` into vectors `X, Y` and output `X . Y mod q`
    output = accumulator = k = (x * y) % q  # exponent = 1   output = xy
    for exponent in range(2, n + 1):
        accumulator = (accumulator * k) % q
        output = (output + accumulator) % q
    return output
