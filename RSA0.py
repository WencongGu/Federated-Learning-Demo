from random import randrange
import math


class RSA:
    RSA_DEFAULT_EXPONENT = 65537
    RSA_DEFAULT_MODULUS_LEN = 2048
    P_experiment = 17
    Q_experiment = 19

    def __init__(self, name, delta_p_q=20, key_bits=RSA_DEFAULT_MODULUS_LEN, exponent=RSA_DEFAULT_EXPONENT,
                 is_default_exponent=True, is_experiment=False):
        self.name = name
        if is_experiment:
            self.p = self.P_experiment
            self.q = self.Q_experiment
            self.e = 144
        # 找出一个e使1<e<(p-1)*(q-1)
        else:
            p = 17
            q = 37
            while abs(p - q) <= delta_p_q:
                p = self.get_random_prime(key_bits // 2)
                q = self.get_random_prime(key_bits // 2)
            self.p = p
            self.q = q

            if is_default_exponent:
                self.e = exponent
            else:
                self.e = randrange(2, (self.p - 1) * (self.q - 1) - 1)
        self.n = self.p * self.q
        self.d = self.invmod(self.e, self.lcm(self.p, self.q - 1))
        self.pub_key = (self.e, self.n)
        self.pri_key = (self.d, self.n)

    @staticmethod
    def is_prime(n):  # 判断一个数是不是素数
        mid = math.sqrt(n)
        mid = math.floor(mid)
        for item in range(2, mid):
            if n % item == 0:
                return False
        return True

    @staticmethod
    def generate_n_bit_odd(n: int):  # 生成大数,不确定是不是素数
        assert n > 1
        return randrange(2 ** (n - 1) + 1, 2 ** n, 2)

    def get_lowlevel_prime(self, num_bits):
        first_50_primes = [2, 3]
        for i in range(first_50_primes[-1] + 1, 235):
            for p in first_50_primes:
                if i % p:
                    continue
                else:
                    break
            else:
                first_50_primes.append(i)
        while True:
            c = self.generate_n_bit_odd(num_bits)
            for divisor in first_50_primes:
                if c % divisor == 0 and divisor ** 2 <= c:
                    break
            return c

    @staticmethod
    def miller_rabin_primality_check(n, k=20):  # 米勒-拉宾素性检验，由于假设n是一个素数，n-1=a^s*d,s和d是常量，改变a的值，检测20次
        assert n > 3
        if n % 2 == 0:
            return False
        # 找出n-1 = 2^s*d
        s, d = 0, n - 1
        while d % 2 == 0:
            d >>= 1
            s += 1

        for _ in range(k):
            a = randrange(2, n - 1)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(s):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def get_random_prime(self, num_bits):  # 获取大素数
        while True:
            p = self.get_lowlevel_prime(num_bits)
            if self.miller_rabin_primality_check(p):
                return p

    @staticmethod
    def gcd(a, b):  # 求最大公约数
        while b:
            a, b = b, a % b
        return a

    def lcm(self, a, b):  # 求最大公倍数
        return a // self.gcd(a, b) * b

    def exgcd(self, a, b):  # 扩展欧几里得算法
        old_s, s = 1, 0
        old_t, t = 0, 1
        while b:
            q = a // b
            s, old_s = old_s - q * s, s
            t, old_t = old_t - q * t, t
            a, b = b, a % b
        return a, old_s, old_t

    def invmod(self, e, m):  # 求模逆元：知道x * e + y * m = g
        g, d, y = self.exgcd(e, m)
        assert g == 1
        if d < 0:
            d += m
        return d

    @staticmethod
    def uint_from_bytes(xbytes: bytes) -> int:  # 比特转换位整数
        return int.from_bytes(xbytes, 'big')

    def uint_to_bytes(self, x: int) -> bytes:  # 整数转换成比特的时候，一个整数对应32位比特数
        if x == 0:
            return bytes(1)
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')  # 做到尽量不补零

    def encrypt(self, data):
        if type(data) == bytes:
            int_data = int.from_bytes(data, 'big')  # 比特转换位整数
            return pow(int_data, self.e, self.n)
        elif type(data) == int:
            return pow(data, self.e, self.n)

    def decrypt(self, encrypted_int_data: int):
        int_data = pow(encrypted_int_data, self.d, self.n)
        return {"int_data": int_data, "bytes_data": self.uint_to_bytes(int_data)}


if __name__ == '__main__':
    alice = RSA("Alice")
    msg = b'Textbook RSA in Python'
    ctxt = alice.encrypt(msg)
    print(ctxt)
    m = alice.decrypt(ctxt)
    print(m)
    print(msg==m["bytes_data"])
