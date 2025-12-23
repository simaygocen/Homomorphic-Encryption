"""A module to perform computations on ciphertexts in BFV."""

from util.ciphertext import Ciphertext
from sympy import Poly, invert
class BFVEvaluator:

    """An instance of an evaluator for ciphertexts.

    This allows us to add, multiply, and relinearize ciphertexts.

    Attributes:
        plain_modulus (int): Coefficient modulus of plaintexts (t).
        coeff_modulus (int): Modulus q of coefficients of polynomial
            ring R_q.
    """

    def __init__(self, params):
        """Inits Evaluator.

        Args:
            params (Parameters): Parameters including polynomial degree,
                plaintext modulus, and ciphertext modulus.
        """
        self.plain_modulus = params.plain_modulus
        self.coeff_modulus = params.ciph_modulus
        self.scaling_factor = params.scaling_factor

    def add(self, ciph1, ciph2):
        """Adds two ciphertexts.

        Adds two ciphertexts within the context.

        Args:
            ciph1 (Ciphertext): First ciphertext.
            ciph2 (Ciphertext): Second ciphertext.

        Returns:
            A Ciphertext which is the sum of the two ciphertexts.
        """
        assert isinstance(ciph1, Ciphertext)
        assert isinstance(ciph2, Ciphertext)

        new_ciph_c0 = ciph1.c0.add(ciph2.c0, self.coeff_modulus)
        new_ciph_c1 = ciph1.c1.add(ciph2.c1, self.coeff_modulus)
        return Ciphertext(new_ciph_c0, new_ciph_c1)

    def multiply(self, ciph1, ciph2, relin_key):
        """Multiplies two ciphertexts.

        Multiplies two ciphertexts within the context, and relinearizes.

        Args:
            ciph1 (Ciphertext): First ciphertext.
            ciph2 (Ciphertext): Second ciphertext.
            relin_key (RelinKey): Relinearization keys.

        Returns:
            A Ciphertext which is the product of the two ciphertexts.
        """
        assert isinstance(ciph1, Ciphertext)
        assert isinstance(ciph2, Ciphertext)

        c0 = ciph1.c0.multiply_fft(ciph2.c0)
        c0 = c0.scalar_multiply(1 / self.scaling_factor)
        c0 = c0.round().mod(self.coeff_modulus)

        c1 = ciph1.c0.multiply_fft(ciph2.c1).add(ciph1.c1.multiply_fft(ciph2.c0))
        c1 = c1.scalar_multiply(1 / self.scaling_factor)
        c1 = c1.round().mod(self.coeff_modulus)

        c2 = ciph1.c1.multiply_fft(ciph2.c1)
        c2 = c2.scalar_multiply(1 / self.scaling_factor)
        c2 = c2.round().mod(self.coeff_modulus)

        return self.relinearize(relin_key, c0, c1, c2)

    def subtract(self, ciph1, ciph2):
        """Subtracts ciph2 from ciph1.

        Subtracts one ciphertext from another within the context.

        Args:
            ciph1 (Ciphertext): The minuend ciphertext.
            ciph2 (Ciphertext): The subtrahend ciphertext.

        Returns:
            A Ciphertext which is the result of subtracting ciph2 from ciph1.
        """
        assert isinstance(ciph1, Ciphertext)
        assert isinstance(ciph2, Ciphertext)

        new_ciph_c0 = ciph1.c0.subtract(ciph2.c0, self.coeff_modulus)
        new_ciph_c1 = ciph1.c1.subtract(ciph2.c1, self.coeff_modulus)
        return Ciphertext(new_ciph_c0, new_ciph_c1)

    def divide(self, ciph1, ciph2, relin_key):
        """Divides one ciphertext by another.

        Divides one ciphertext by another within the context, and relinearizes.

        Args:
            ciph1 (Ciphertext): Numerator ciphertext.
            ciph2 (Ciphertext): Denominator ciphertext.
            relin_key (RelinKey): Relinearization keys.

        Returns:
            A Ciphertext which is the result of dividing the first ciphertext by the second.
        """
        assert isinstance(ciph1, Ciphertext)
        assert isinstance(ciph2, Ciphertext)

        # Calculate 1 / ciph2
        ciph2_inverse = self.ntt(ciph2, relin_key)

        # Multiply ciph1 with the inverse of ciph2
        result = self.multiply(ciph1, ciph2_inverse, relin_key)

        return result

    def relinearize(self, relin_key, c0, c1, c2):
        """Relinearizes a 3-dimensional ciphertext.

        Reduces 3-dimensional ciphertext back down to 2 dimensions.

        Args:
            relin_key (RelinKey): Relinearization keys.
            c0 (Polynomial): First component of ciphertext.
            c1 (Polynomial): Second component of ciphertext.
            c2 (Polynomial): Third component of ciphertext.

        Returns:
            A Ciphertext which has only two components.
        """
        keys = relin_key.keys
        base = relin_key.base
        num_levels = len(keys)

        c2_decomposed = c2.base_decompose(base, num_levels)

        new_c0 = c0
        new_c1 = c1

        for i in range(num_levels):
            new_c0 = new_c0.add(keys[i][0].multiply(c2_decomposed[i], self.coeff_modulus), self.coeff_modulus)
            new_c1 = new_c1.add(keys[i][1].multiply(c2_decomposed[i], self.coeff_modulus), self.coeff_modulus)

        return Ciphertext(new_c0, new_c1)