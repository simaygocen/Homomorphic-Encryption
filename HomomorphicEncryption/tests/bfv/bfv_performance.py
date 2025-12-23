"""

Need to run test with a command line argument for the polynomial degree.
For multiplication with polynomial degree 16, run
python3 run_bfv_performance.py TestMultiply 16"""

import os
import sys
import time
import unittest
import colorama
from colorama import Fore, Back, Style


from bfv.bfv_decryptor import BFVDecryptor
from bfv.bfv_encryptor import BFVEncryptor
from bfv.bfv_evaluator import BFVEvaluator
from bfv.bfv_key_generator import BFVKeyGenerator
from bfv.bfv_parameters import BFVParameters
from util.plaintext import Plaintext
from util.polynomial import Polynomial


TEST_DIRECTORY = os.path.dirname(__file__)
arg = None

class TestEvaluator(unittest.TestCase):

    colorama.init(autoreset=True)

    def setUp(self):
        self.degree = int(arg)
        self.plain_modulus = 256
        self.ciph_modulus = 8000000000000
        self.params = BFVParameters(poly_degree=self.degree,
                                    plain_modulus=self.plain_modulus,
                                    ciph_modulus=self.ciph_modulus)
        key_generator = BFVKeyGenerator(self.params)
        public_key = key_generator.public_key
        secret_key = key_generator.secret_key
        self.relin_key = key_generator.relin_key
        self.encryptor = BFVEncryptor(self.params, public_key)
        self.decryptor = BFVDecryptor(self.params, secret_key)
        self.evaluator = BFVEvaluator(self.params)


    def run_test_multiply(self, message1, message2):
        poly1 = Polynomial(self.degree, message1)
        poly2 = Polynomial(self.degree, message2)
        plain1 = Plaintext(poly1)
        print(Fore.GREEN+Style.BRIGHT+"Plain1:", Style.BRIGHT+str(plain1))
        plain2 = Plaintext(poly2)
        print(Fore.GREEN+Style.BRIGHT+"Plain2:", Style.BRIGHT+str(plain2))
        plain_prod = Plaintext(poly1.multiply(poly2, self.plain_modulus))
        ciph1 = self.encryptor.encrypt(plain1)
        ciph2 = self.encryptor.encrypt(plain2)
        start_time = time.perf_counter()
        ciph_prod = self.evaluator.multiply(ciph1, ciph2, self.relin_key)
        total_time = time.perf_counter() - start_time
        decrypted_prod = self.decryptor.decrypt(ciph_prod)
        print(Fore.YELLOW+Style.BRIGHT+"Plain Prod:", Style.BRIGHT+str(plain_prod))
        self.assertEqual(str(plain_prod), str(decrypted_prod))
        return total_time, ciph1, ciph2, ciph_prod,decrypted_prod

    def run_test_add(self, message1, message2):
        poly1 = Polynomial(self.degree, message1)
        poly2 = Polynomial(self.degree, message2)
        plain1 = Plaintext(poly1)
        print(Fore.GREEN+Style.BRIGHT+"Plain1:", Style.BRIGHT+str(plain1))
        plain2 = Plaintext(poly2)
        print(Fore.GREEN+Style.BRIGHT+"Plain2:", Style.BRIGHT+str(plain2))
        plain_add = Plaintext(poly1.add(poly2, self.plain_modulus))
        ciph1 = self.encryptor.encrypt(plain1)
        ciph2 = self.encryptor.encrypt(plain2)
        start_time = time.perf_counter()
        ciph_add = self.evaluator.add(ciph1, ciph2)
        total_time = time.perf_counter() - start_time
        decrypted_add = self.decryptor.decrypt(ciph_add)
        print(Fore.YELLOW + Style.BRIGHT + "Plain Add:", Style.BRIGHT + str(plain_add))
        self.assertEqual(str(plain_add), str(decrypted_add))
        return total_time, ciph1, ciph2, ciph_add,decrypted_add

    def run_test_subtract(self, message1, message2):
        poly1 = Polynomial(self.degree, message1)
        poly2 = Polynomial(self.degree, message2)
        plain1 = Plaintext(poly1)
        print(Fore.GREEN+Style.BRIGHT+"Plain1:", Style.BRIGHT+str(plain1))
        plain2 = Plaintext(poly2)
        print(Fore.GREEN+Style.BRIGHT+"Plain2:", Style.BRIGHT+str(plain2))
        plain_subtract = Plaintext(poly1.subtract(poly2, self.plain_modulus))
        ciph1 = self.encryptor.encrypt(plain1)
        ciph2 = self.encryptor.encrypt(plain2)
        start_time = time.perf_counter()
        ciph_subtract = self.evaluator.subtract(ciph1, ciph2)
        total_time = time.perf_counter() - start_time
        decrypted_subtract = self.decryptor.decrypt(ciph_subtract)
        print(Fore.YELLOW + Style.BRIGHT + "Plain Subtract:", Style.BRIGHT + str(plain_subtract))
        self.assertEqual(str(plain_subtract), str(decrypted_subtract))
        return total_time, ciph1, ciph2, ciph_subtract,decrypted_subtract

    def test_evaluator_time(self):
        self.params.print_parameters()
        total_time = 0
        vec1 = [246, 211, 243, 250, 152, 111, 147, 153, 73, 244, 58, 61, 63, 49, 93, 168]
        print(Fore.BLUE+Style.BRIGHT+"Vector 1: ", Style.BRIGHT+str(vec1))
        vec2 = [24, 122, 109, 170, 26, 28, 180, 110, 39, 223, 78, 100, 177, 114, 3, 91]
        print(Fore.BLUE+Style.BRIGHT+"Vector 2: ",Style.BRIGHT+str(vec2))
        time_taken, encrypted_text1, encrypted_text2, encrypted_add, decrypted_add = self.run_test_add(
            vec1, vec2)
        total_time += time_taken
        # print(Fore.CYAN + Style.BRIGHT + "CipherText of Plain1: ", Style.BRIGHT + str(encrypted_text1))
        # print(Fore.CYAN + Style.BRIGHT + "CipherText of Plain2: ", Style.BRIGHT + str(encrypted_text2))
        # print(Fore.YELLOW + Style.BRIGHT + "CipherText of Plain1 + Plain2: ", Style.BRIGHT + str(encrypted_add))
        print(Fore.MAGENTA + Style.BRIGHT + "Decryption of CipherText of Plain1 + Plain2 : ",
              Style.BRIGHT + str(decrypted_add))
        print(Fore.RED + Style.BRIGHT + "Average time add operation: %s%f seconds%s" % (
            Fore.CYAN + Style.BRIGHT, total_time, Fore.RESET))
        print(Fore.YELLOW + Style.BRIGHT + "-----------------------------------------------")
        total_time=0
        time_taken, encrypted_text1, encrypted_text2, encrypted_subtract, decrypted_subtract = self.run_test_subtract(vec1, vec2)
        total_time += time_taken
        # print(Fore.CYAN + Style.BRIGHT + "CipherText of Plain1: ", Style.BRIGHT + str(encrypted_text1))
        # print(Fore.CYAN + Style.BRIGHT + "CipherText of Plain2: ", Style.BRIGHT + str(encrypted_text2))
        # print(Fore.YELLOW + Style.BRIGHT + "CipherText of Plain1 - Plain2: ", Style.BRIGHT + str(encrypted_subtract))
        print(Fore.MAGENTA + Style.BRIGHT + "Decryption of CipherText of Plain1 - Plain2 : ",
              Style.BRIGHT + str(decrypted_subtract))
        print(Fore.RED + Style.BRIGHT + "Average time subtract operation: %s%f seconds%s" % (
            Fore.CYAN + Style.BRIGHT, total_time, Fore.RESET))
        print(Fore.YELLOW + Style.BRIGHT + "-----------------------------------------------")
        total_time=0
        time_taken, encrypted_text1, encrypted_text2, encrypted_product , decrypted_prod= self.run_test_multiply(vec1, vec2)
        total_time +=time_taken
        # print(Fore.CYAN+ Style.BRIGHT +"CipherText of Plain1: ", Style.BRIGHT + str(encrypted_text1))
        # print(Fore.CYAN+ Style.BRIGHT +"CipherText of Plain2: ", Style.BRIGHT + str(encrypted_text2))
        # print(Fore.YELLOW+ Style.BRIGHT +"CipherText of Plain1 * Plain2: ", Style.BRIGHT + str(encrypted_product))
        print(Fore.MAGENTA + Style.BRIGHT +"Decryption of CipherText of Plain1 * Plain2 : ", Style.BRIGHT + str(decrypted_prod))
        print(Fore.RED + Style.BRIGHT + "Average time multiply operation: %s%f seconds%s" % (
            Fore.CYAN + Style.BRIGHT, total_time, Fore.RESET))


if __name__ == '__main__':
    arg = sys.argv[2]
    sys.argv = sys.argv[:2]
    res = unittest.main(verbosity=3, exit=False)
