"""A module to keep track of parameters for the BFV scheme."""

import math
import colorama
from colorama import Fore, Back, Style
class BFVParameters:

    """An instance of parameters for the BFV scheme.

    Attributes:
        poly_degree (int): Degree d of polynomial that determines the
            quotient ring R.
        plain_modulus (int): Coefficient modulus of plaintexts (t).
        ciph_modulus (int): Coefficient modulus of ciphertexts (q).
    """

    def __init__(self, poly_degree, plain_modulus, ciph_modulus):
        """Inits Parameters with the given parameters.

        Args:
            poly_degree (int): Degree d of polynomial of ring R.
            plain_modulus (int): Coefficient modulus of plaintexts.
            ciph_modulus (int): Coefficient modulus of ciphertexts.
        """
        self.poly_degree = poly_degree
        self.plain_modulus = plain_modulus
        self.ciph_modulus = ciph_modulus
        self.scaling_factor = self.ciph_modulus / self.plain_modulus

    def print_parameters(self):
        """Prints parameters.
        """

        print(Fore.MAGENTA+Style.BRIGHT+"Encryption parameters")
        print(Fore.LIGHTYELLOW_EX+Style.BRIGHT+"\t polynomial degree: %d" % (Style.BRIGHT,self.poly_degree))
        print(Fore.LIGHTYELLOW_EX+Style.BRIGHT+"\t plaintext modulus: %d" % (Style.BRIGHT,self.plain_modulus))
        print(Fore.LIGHTYELLOW_EX+Style.BRIGHT+"\t ciphertext modulus size: %d bits" % (Style.BRIGHT, int(math.log(self.ciph_modulus, 2))))
