# MT19937 constants defined on https://en.wikipedia.org/wiki/Mersenne_Twister
W = 32  # word size
N = 624  # degree of recurrence
M = 397  # middle word
R = 31  # separation point of one word
A = 0x9908B0DF  # coefficients of the rational normal form twist matrix
U = 11  # bitmasks
D = 0xFFFFFFFF  # bitmasks
S = 7  # TGFSR(R) tempering bit shifts
B = 0x9D2C5680  # TGFSR(R) tempering bitmask
T = 15  # TGFSR(R) tempering bit shifts
C = 0xEFC60000  # TGFSR(R) tempering bitmask
L = 18  # bitmasks
F = 1812433253

BITMASK_32_BIT = 0x00FFFFFF


class MersenneTwister(object):
    """This was done following the pseudocode at https://en.wikipedia.org/wiki/Mersenne_Twister"""

    def __init__(self, seed) -> None:
        self.mt = [0] * N  # stores generator state
        self.index = N + 1
        self.lower_mask = (1 << R) - 1
        self.upper_mask = (
            ~self.lower_mask & BITMASK_32_BIT
        )  # lowest w bits of (not lower_mask)
        self.seed_mt(seed)

    def seed_mt(self, seed: int) -> None:
        """Initialize the generator from a seed"""
        self.index = N
        self.mt[0] = seed
        for i in range(N - 1):
            self.mt[i] = (
                F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))) + i
            ) & BITMASK_32_BIT

    def extract_number(self):
        """Extract a tempered value based on MT[index] calling twist() every n numbers"""
        if self.index >= N:
            if self.index > N:
                raise Exception("Generator was not seeded!")
            self.twist()

        y = self.mt[self.index]
        y = y ^ ((y >> U) & D)
        y = y ^ ((y << S) & B)
        y = y ^ ((y >> T) & C)
        y = y ^ (y >> 1)

        self.index = self.index + 1
        return y & BITMASK_32_BIT

    def twist(self):
        """Generate the next n values from the series x_i"""
        for i in range(N - 1):
            x = (self.mt[i] & self.upper_mask) + (self.mt[i + 1 % N] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ A
            self.mt[i] = self.mt[(i + M) % N] ^ xA
        self.index = 0
