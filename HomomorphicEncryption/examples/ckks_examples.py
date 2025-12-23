

from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_encoder import CKKSEncoder
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_parameters import CKKSParameters
import colorama
from colorama import Fore, Back, Style
import time

def main():
    colorama.init(autoreset=True)
    poly_degree =8
    ciph_modulus = 1 << 600
    bit_length = ciph_modulus.bit_length()
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    bit_length2 = scaling_factor.bit_length()
    print(Fore.LIGHTRED_EX+ Style.BRIGHT + "Polynom Degree: ", Style.BRIGHT+str(poly_degree))
    print(Fore.LIGHTRED_EX+ Style.BRIGHT + "Cipher Modulus Bits: ", Style.BRIGHT+str(bit_length))
    print(Fore.LIGHTRED_EX + Style.BRIGHT + "Scaling Factor Bits: " ,Style.BRIGHT+str(bit_length2))
    params = CKKSParameters(poly_degree=poly_degree,
                            ciph_modulus=ciph_modulus,
                            big_modulus=big_modulus,
                            scaling_factor=scaling_factor)
    key_generator = CKKSKeyGenerator(params)
    public_key = key_generator.public_key
    secret_key = key_generator.secret_key
    relin_key = key_generator.relin_key
    encoder = CKKSEncoder(params)
    encryptor = CKKSEncryptor(params, public_key, secret_key)
    decryptor = CKKSDecryptor(params, secret_key)
    evaluator = CKKSEvaluator(params)

    message1 = [0.5, 0.3 + 0.2j, 0.78, 0.88j]
    message2 = [0.2, 0.11, 0.4 + 0.67j, 0.9 + 0.99j]
    print(Fore.GREEN + Style.BRIGHT + "Message1: ", Style.BRIGHT + str(message1))
    print(Fore.GREEN + Style.BRIGHT + "Message2:", Style.BRIGHT + str(message2))

    plain1 = encoder.encode(message1, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message1 : ", Style.BRIGHT + str(plain1))
    plain2 = encoder.encode(message2, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message2 : ", Style.BRIGHT + str(plain2))
    decoded_plain1 =encoder.decode(plain1)
    decoded_plain2 = encoder.decode(plain2)
    print(Fore.BLUE+Style.BRIGHT+"Reel Numbers plaintext decoded of message1:" , Style.BRIGHT+str(decoded_plain1))
    print(Fore.BLUE+Style.BRIGHT+"Reel Numbers plaintext decoded of message2:" , Style.BRIGHT+str(decoded_plain2))
    result_add = [x * y for x, y in zip(message1, message2)]
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Expected Multiply Result is:", Style.BRIGHT + str(result_add))
    ciph1 = encryptor.encrypt(plain1)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph1))
    ciph2 = encryptor.encrypt(plain2)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph2))
    start_time = time.perf_counter()
    ciph_add = evaluator.multiply(ciph1, ciph2,relin_key)
    total_time = time.perf_counter() - start_time
    print(Fore.RED + Style.BRIGHT + "CipherText of message1*message2: ", Style.BRIGHT + str(ciph_add))
    decrypted_add= decryptor.decrypt(ciph_add)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "CiphertText to Polynomial PlainText: ",Style.BRIGHT + str(decrypted_add))
    decoded_add= encoder.decode(decrypted_add)
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Reel Numbers PlainText Result :", Style.BRIGHT + str(decoded_add))
    print(Fore.RED + Style.BRIGHT + "Total Time of Multiply operation:", total_time)
    print(Fore.YELLOW + Style.BRIGHT +"--------------------------------------------------------------------")

    message1 = [0.5, 0.3 + 0.2j, 0.78, 0.88j]
    message2 = [0.2, 0.11, 0.4 + 0.67j, 0.9 + 0.99j]
    print(Fore.GREEN + Style.BRIGHT + "Message1: ", Style.BRIGHT + str(message1))
    print(Fore.GREEN + Style.BRIGHT + "Message2:", Style.BRIGHT + str(message2))

    plain1 = encoder.encode(message1, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message1 : ", Style.BRIGHT + str(plain1))
    plain2 = encoder.encode(message2, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message2 : ", Style.BRIGHT + str(plain2))
    decoded_plain1 = encoder.decode(plain1)
    decoded_plain2 = encoder.decode(plain2)
    print(Fore.BLUE + Style.BRIGHT + "Reel Numbers plaintext decoded of message1:", Style.BRIGHT + str(decoded_plain1))
    print(Fore.BLUE + Style.BRIGHT + "Reel Numbers plaintext decoded of message2:", Style.BRIGHT + str(decoded_plain2))
    result_subtract = [x - y for x, y in zip(message1, message2)]
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Expected Subtract Result is:", Style.BRIGHT + str(result_subtract))
    ciph1 = encryptor.encrypt(plain1)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph1))
    ciph2 = encryptor.encrypt(plain2)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph2))
    start_time = time.perf_counter()
    ciph_subtract = evaluator.subtract(ciph1, ciph2)
    total_time = time.perf_counter() - start_time
    print(Fore.RED + Style.BRIGHT + "CipherText of message1-message2: ", Style.BRIGHT + str(ciph_subtract))
    decrypted_subtract = decryptor.decrypt(ciph_subtract)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "CiphertText to Polynomial PlainText: ",
          Style.BRIGHT + str(decrypted_subtract))
    decoded_subtract = encoder.decode(decrypted_subtract)
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Reel Numbers PlainText Result :", Style.BRIGHT + str(decoded_subtract))
    print(Fore.RED + Style.BRIGHT + "Total Time of Subtract operation:", total_time)
    print(Fore.YELLOW + Style.BRIGHT + "--------------------------------------------------------------------")

    message1 = [0.5, 0.3 + 0.2j, 0.78, 0.88j]
    message2 = [0.2, 0.11, 0.4 + 0.67j, 0.9 + 0.99j]
    print(Fore.GREEN + Style.BRIGHT + "Message1: ", Style.BRIGHT + str(message1))
    print(Fore.GREEN + Style.BRIGHT + "Message2:", Style.BRIGHT + str(message2))

    plain1 = encoder.encode(message1, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message1 : ", Style.BRIGHT + str(plain1))
    plain2 = encoder.encode(message2, scaling_factor)
    print(Fore.GREEN + Style.BRIGHT + "Polynomial plaintext of message2 : ", Style.BRIGHT + str(plain2))
    decoded_plain1 = encoder.decode(plain1)
    decoded_plain2 = encoder.decode(plain2)
    print(Fore.BLUE + Style.BRIGHT + "Reel Numbers plaintext decoded of message1:", Style.BRIGHT + str(decoded_plain1))
    print(Fore.BLUE + Style.BRIGHT + "Reel Numbers plaintext decoded of message2:", Style.BRIGHT + str(decoded_plain2))
    result_multiply = [x * y for x, y in zip(message1, message2)]
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Expected Multiply Result is:", Style.BRIGHT + str(result_multiply))
    ciph1 = encryptor.encrypt(plain1)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph1))
    ciph2 = encryptor.encrypt(plain2)
    print(Fore.MAGENTA + Style.BRIGHT + "CipherText of message1:", Style.BRIGHT + str(ciph2))
    start_time = time.perf_counter()
    ciph_multiply= evaluator.multiply(ciph1, ciph2,relin_key)
    total_time = time.perf_counter() - start_time
    print(Fore.RED + Style.BRIGHT + "CipherText of message1*message2: ", Style.BRIGHT + str(ciph_multiply))
    decrypted_multiply = decryptor.decrypt(ciph_multiply)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "CiphertText to Polynomial PlainText: ",
          Style.BRIGHT + str(decrypted_multiply))
    decoded_multiply = encoder.decode(decrypted_multiply)
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Reel Numbers PlainText Result :", Style.BRIGHT + str(decoded_multiply))
    print(Fore.RED + Style.BRIGHT + "Total Time of Multiply operation:", total_time)
    print(Fore.YELLOW + Style.BRIGHT + "--------------------------------------------------------------------")


if __name__ == '__main__':
    main()
