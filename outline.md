Assign the vector `A` to some public constant and define `F(X) -> A . X`

Given

    y = A . X

for a known vector `A`, recovering `X` from (A, y) is an NP-complete problem.

There exists some parameterization of this problem that is hard to solve.
- The dimension of the vectors and the size of the coefficients (or modulus) may influence the difficulty of the problem

For such parameters, given `(A, F(X))` there does not exist a polynomial time adversary that can recover X unless P = NP.

The above operation is commonly known as the "dot product".
The dot product has a number of algebraic relationships.
The relationships of interest here are:

    F(X) + F(Y) = F(X + Y)
    s * F(X) = F(s * X)

These relationships, coupled with the one-way nature of `F`, can be used to instantiate a variety of cryptographic schemes ranging from digital signatures to public-key encryption.

Digital Signatures
==================
Basic process
-------------
Key Generation:
- Private key: A tuple of `k` random vectors suitable for `F`
- Public key: A vector of `F(x)`, each entry `x` is in the private key
    - In list-builder notation: [F(X) for X in private_key]
- Security:
    - Security of each entry in the key follows immediately from the definition of F

Sign:
- Generate k challenge bits `r` (commonly done via `h(m)` or something similar)
    - `r` can be viewed as a k-dimensional vector with coefficients in (0, 1)
- Sum together the private-key vectors indicated by the challenge bits
- The sum is the signature
- Security:
    - `signature` vector provides multiple equations with the same solution
    - `signature` vector leaks information about the private key

Verify:
- Generate/obtain the challenge bits
- Sum together the public-key scalars indicated by the challenge bits to obtain the verifier
    - Equivalent to `public_key . r`
- Verify that  `F(signature) == publickey . r`
- Security:
    - Given `publickey` and any `verifier`, recovering a suitable `r` such that `verifier = publickey . r` is intractable because it implies the ability to invert `F`
    - Given `verifier = F(signature)`, recovering `signature` is intractable because it implies the ability to invert `F`

Issues
------
The signatures in this scheme leak information about the private key.
A possible solution is to amend the process to include a second, randomly generated public key in the signing process:

Key Generation:
- same as before

Sign:
- Generate a second keypair
- Add the private keys together to form a new private key
- Add the public keys together to form a new public key
- Sum together the vectors from the randomized private key, as indicated by the challenge bits
- The sum and second public key are the signature
- Security:
    - Additional random variables from the second private key mask the real private key
    - Information leakage is stemmed; number of unknowns > number of equations

Verify:
- Add the second public key to the original to obtain to the randomized public key
- Compute the dot product between the randomized public key and the challenge bits
- Verify that  `F(signature) == (publickey + publickey2) . r`
- Security is the same as before

Issues
------
The subset sum problem is not friendly in regards to space.
Estimates indicate a space cost of O(2^8n) bits for n-bit (post-quantum) security level.
- 128-bit security level requires approximately 2^20 bits of space

A good hard problem to use is the dot product.
The subset-sum problem is typically modeled as the dot product between a known vector and unknown binary vector.

The question then, is how generate compressable vectors within the additional constraints of the parameterization of the problem.

Proposed Solution
-----------------
Generate a random scalar `s` uniform mod `q`

Create the vector `S = s^1, s^2, s^3, ... s^n` (mod q)

Apply a random permutation matrix `P` to get a shuffled vector `S' = PS`

An n-dimension uniformly random vector mod `q` requires `n * log2(q)` bits of space.
The proposed vector type requires `log2(n!) + log2(q)` bits of space when compressed.

As for the security, these changes would add non-linearity and a combinatoric property to the problem. It seems unlikely that these could make the problem easier, but this does not constitute proof.

However, the ideal parameters that ensure the problems hardness have yet to be established.
It could be the case that:

- The problem is hard whenever the solution is any non-sparse vector
- The problem is hard whenever the solution is any vector with a small norm
- The problem is hard whenever ... ?


Parameters
==========
Assume the coefficients of `X` are in `(0, 1)`, then the problem is the subset-sum problem.

For the subest sum problem, estimates show that a post-quantum security level of `n` bits requires vectors of dimension `8n` with coefficients of size `log2(q) = 8n`.

In the case of the subset-sum problem, a critical factor for determining whether the problem is hard at all is the *density*. Is there an equivalent metric for the dot product in general?

How does security scale as the coefficients of `X` grow larger?


Compressing permutation matrices
================================

Strategy 1
----------
Compression: For each row, record the number of zeros before a 1 is placed.

Decompress: add x zeros, a 1, then fill the row with zeros

Cost: n * log2(n)

Strategy 2
----------
View the matrix as a sequence of 2^i, 2^j, ... 2^k

Find a polynomial that generates the sequence i, j, ..., k

Cost: Not yet tested
