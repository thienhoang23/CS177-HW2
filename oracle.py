# CS177 -- padding oracle attacks This code is (unfortunately) meant
# to be run with Python 2.7.10 on the CSIL cluster
# machines. Unfortunately, cryptography libraries are not available
# for Python3 at present, it would seem.
from Crypto.Cipher import AES
import binascii
import sys

def check_enc(text):
    nl = len(text)
    val = int(binascii.hexlify(text[-1]), 16)
    if val == 0 or val > 16:
        return False

    for i in range(1,val+1):
        if (int(binascii.hexlify(text[nl-i]), 16) != val):
            return False
    return True
                                 
def PadOracle(ciphertext):
    if len(ciphertext) % 16 != 0:
        return False
    
    tkey = 'Sixteen byte key'

    ivd = ciphertext[:AES.block_size]
    dc = AES.new(tkey, AES.MODE_CBC, ivd)
    ptext = dc.decrypt(ciphertext[AES.block_size:])

    return check_enc(ptext)


# Padding-oracle attack comes here

def PaddingOracleAttack(ctext, block_size):
    num_block = len(ctext) / block_size;
    plaintext = ""
    for i in range(1, num_block): # for the entire message
        last_block = ctext[-block_size:]
        second_to_last_block = ctext[-2*block_size:-block_size]
        correct_guesses = []
        for byte_pos in range(1, block_size+1): #for each block, count backward starting at 1
            valid_guesses = []
            for guess in range(0,256): # for each byte
                new_byte = byte_pos ^ guess ^ ord(second_to_last_block[block_size-byte_pos:block_size-byte_pos+1])
                mod_second_to_last_block = second_to_last_block[:-byte_pos]
                mod_second_to_last_block = mod_second_to_last_block + chr(new_byte)
                for x in range(1,byte_pos):
                    mod_second_to_last_block = mod_second_to_last_block + chr(ord(second_to_last_block[block_size-byte_pos+x:block_size-byte_pos+x+1]) ^ byte_pos ^ correct_guesses[x-1])
                spoofed_ctext = ctext[:-2*block_size] + mod_second_to_last_block + last_block
                if(PadOracle(spoofed_ctext) == True):
                    valid_guesses.append(guess)
            if(len(valid_guesses) == 1):
                plaintext = plaintext + chr(valid_guesses[0])
                correct_guesses.insert(0, valid_guesses[0])
            else:
                for valid_guess in valid_guesses:
                    byte_before = ord(second_to_last_block[block_size-byte_pos-1:block_size-byte_pos])
                    mod_byte_before = byte_before + 1 if byte_before < 255 else byte_before - 1
                    new_byte = byte_pos ^ valid_guess ^ ord(second_to_last_block[block_size - byte_pos:block_size - byte_pos + 1])
                    mod_second_to_last_block = second_to_last_block[:-byte_pos-1] + chr(mod_byte_before) + chr(new_byte)
                    for x in range(1,byte_pos):
                        mod_second_to_last_block = mod_second_to_last_block + chr(ord(second_to_last_block[block_size-byte_pos+x:block_size-byte_pos+x+1]) ^ byte_pos ^ correct_guesses[x-1]) 
                    spoofed_ctext = ctext[:-2*block_size] + mod_second_to_last_block + last_block
                    if(PadOracle(spoofed_ctext) == True):
                        plaintext = plaintext + chr(valid_guess)
                        correct_guesses.insert(0,valid_guess)
                        break
        ctext = ctext[:-16]

    return plaintext[::-1]



if len(sys.argv) > 1:
    myfile = open(sys.argv[1], "rb")
    ctext=myfile.read()
    myfile.close()

    # complete from here. The ciphertext is now (hopefull) stored in
    # ctext as a string. Individual symbols can be accessed as
    # int(ctext[i]). Some more hints will be given on the Piazza
    # page.


    block_size = 16;
    plaintext = PaddingOracleAttack(ctext, block_size)
    print plaintext

    # end completing here, leave rest unchanged.
else:
    print("You need to specify a file!")