def dotproduct(v1, v2):
    return sum(v1[i] * v2i for i, v2i in enumerate(v2))

def mmul(m, v, dot=dotproduct):
    try:
        return [dot(row, v) for row in m]
    except (OverflowError, TypeError):
        return [[dot(row, _v) for row in m] for _v in v]

def scale_vector(v, s, q):
    return [(x * s) % q for x in v]

def add_vector(v1, v2, q):
    return [(v1[i] + v2[i]) % q for i in range(len(v1))]
