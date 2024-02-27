#Homework 2, Number 6
#Sarah Cullinan
#Computer Security 

from Crypto.Cipher import DES

#Step 1: Generate round keys
def generate_round_keys(key):
    #permutation table 1 from slides
    #56 bits 
    pc_1 = [56, 48, 40, 32, 24, 16, 8,
           0, 57, 49, 41, 33, 25, 17,
           9, 1, 58, 50, 42, 34, 26,
           18, 10, 2, 59, 51, 43, 35,
           62, 54, 46, 38, 30, 22, 14,
           6, 61, 53, 45, 37, 29, 21,
           13, 5, 60, 52, 44, 36, 28,
           20, 12, 4, 27, 19, 11, 3]

    #permutation table 2 from slides
    #48 bits
    pc_2 = [13, 16, 10, 23, 0, 4,
           2, 27, 14, 5, 20, 9,
           22, 18, 11, 3, 25, 7,
           15, 6, 26, 19, 12, 1,
           40, 51, 30, 36, 46, 54,
           29, 39, 50, 44, 32, 47,
           43, 48, 38, 55, 33, 52,
           45, 41, 49, 35, 28, 31]

    # the key must be 64 bits, add 0's to the end if not 
    key = key.ljust(64, '0')[:64]

    # key after permutated once
    key_pc = [key[pc_1[i]] for i in range(56)]
    #print("Key afted PC-1", key_pc)

    #reverse generation of roundkeys 
    round_keys = []

    #there are 16 subkeys, each of which is 48 bits long 
    # drop every 8th bit and permute 
    num_keys = 16
    num_bits = 48
    
    for i in range(num_keys):
        #split the key in half, then left rotate each 
        #determine number of left shifts based on iteration number
        #concatenate left and right
        if i in [0, 1, 8, 15]:
            key_pc = key_pc[1:] + key_pc[:1]
        else:
            key_pc = key_pc[2:] + key_pc[:2]

        # each key is 48-bits long
        
        #then permutated for the second time
        round_key = ''.join([key_pc[pc_2[j]] for j in range(num_bits)])
        round_keys.append(round_key)

    return round_keys

#Step 2: decrypt message 
#DES decryption for ECB
def des_ecb_decryption(ciphertext, key):

    #decode each 64-bit block of data 
    decipher = DES.new(key, DES.MODE_ECB)

    #find bytes
    deciphered_bytes = decipher.decrypt(ciphertext)

    #convert bytes to text
    deciphered_text = deciphered_bytes.decode('utf-8')

    return deciphered_text


def main():
    ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
    key = "0100110001001111010101100100010101000011010100110100111001000100"

    #need to turn these text variables into bytes to be able to decode 
    ciphertext_bytes = bytes(int(ciphertext[i:i+8], 2) for i in range(0, len(ciphertext), 8))
    key_bytes = bytes(int(key[i:i+8], 2) for i in range(0,len(key), 8))

    #Step 1: Generate the round keys
    round_keys = generate_round_keys(key)

    #print the round keys
    print("Generated Round Keys:")
    for i, key in enumerate(round_keys, 1):
        print(f"K{i}: {key}")

    #Step 2: DES decryption
    #ECB mode 
    deciphered_text = des_ecb_decryption(ciphertext_bytes,key_bytes)

    print("Deciphered Message:", deciphered_text)

if __name__ == "__main__":
    main()