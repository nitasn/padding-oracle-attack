###########################################
###             S T E P   1             ###
###########################################

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

###########################################
###             S T E P   2             ###
###########################################

plaintext = b'Hello World'

"""
Steps 7 - 11 assume `padded_plaintext` has two blocks.
In step 12, we write general code for any number of blocks.

If you want to try different a plaintext, comment out steps 7 - 11.
"""

padded_plaintext = pad(plaintext, DES.block_size)

###########################################
###             S T E P   3             ###
###########################################

ZEROS_BLOCK = b'\x00' * DES.block_size

KEY = b'poaisfun'

""" You can plug any block for IV. The ZEROS_BLOCK is just an example. """
IV = ZEROS_BLOCK

ciphertext = DES.new(KEY, DES.MODE_CBC, IV).encrypt(padded_plaintext)

###########################################
###             S T E P   4             ###
###########################################

decryptor = DES.new(KEY, DES.MODE_CBC, IV)

"""
Making sure the unpadded decrypted ciphertext matches the plaintext.
"""

assert unpad(decryptor.decrypt(ciphertext), DES.block_size) == plaintext

del decryptor

###########################################
###             S T E P   5             ###
###########################################

"""
A simple trinary xor function.
"""

def xor(a, b, c):
    return a ^ b ^ c

###########################################
###             S T E P   6             ###
###########################################

def oracle(ciphertext):
    """
    Intenrally attempts to decipher the input and to to unpad it;
    Returns True if successful, or False if input is malformed.
    """
    decryptor = DES.new(KEY, DES.MODE_CBC, IV)
    try:
        unpad(decryptor.decrypt(ciphertext), DES.block_size)
        return True
    except ValueError:
        return False


assert oracle(ciphertext) == True
assert oracle(b'garbage') == False

###########################################
###             S T E P   7             ###
###########################################

"""
We will apply a "Padding Oracle Attack" to retrieve the plaintext :)
In our case, the ciphertext is composed of these 2 blocks:
    C1 = 33 aa a3 1 7e 45 33 7b
    C2 = d3 63 42 b3 92 b e6 56
    
Let's start by replacing C1 with zeros.
"""

c = bytearray(ZEROS_BLOCK + ciphertext[DES.block_size :])

###########################################
###             S T E P   8             ###
###########################################

"""
Increment the first block's last byte until the oracle says its valid!
"""

while not oracle(c):
    c[DES.block_size - 1] += 1

###########################################
###             S T E P   9             ###
###########################################

"""
Denote P  = the padded plaintext
Denote C  = the ciphertext
Denote C' = the "ciphertext" we send to the oracle (as opposied to the real ciphertext)
Denote P' = what the oracle thinks the padded plaintext is

we know that    P'2 = D(C2) ^ C'1

by definition   C2 = E(P2 ^ C1)

we'll plug C2   P'2 = D(E(P2 ^ C1)) ^ C'1

and hence       P'2 = P2 ^ C1 ^ C'1

Knowing that P'2 is valid, we deduce that last byte of P'2 is 0x1,
as P'2 was parsed by the oracle as a 7 bytes of data + 1 byte of padding.

It might be possible that P'2 is valid because by chance D(C2)'s second to last byte is 0x2,
and so the last byte of P'2 is 0x2, but we'll discard this option.

Xor is done bitwise, and hence

                P'2[last] = P2[last] ^ C1[last] ^ C'1[last]
                
                0x1 = P2[last] ^ C1[last] ^ C'1[last]
                
                P2[last] = 0x1 ^ C1[last] ^ C'1[last]
"""

P2_last = xor(0x1, ciphertext[DES.block_size - 1], c[DES.block_size - 1])

assert P2_last == padded_plaintext[-1]

"""
>>> print(P2_last)  # prints 0x5

We've successfuly extracted the plaintext's last byte!
"""

###########################################
###            S T E P   1 0            ###
###########################################

"""
To continue to the next (i.e. the second to last) byte of P2,
we'll change c so that the oracle will think the last TWO bytes of P'2 are 0x2 0x2.
"""

c[DES.block_size - 1] ^= 0x1 ^ 0x2

while not oracle(c):
    c[DES.block_size - 2] += 1

"""
Like Step 9, we know that

                P'2 = P2 ^ C1 ^ C'1

                P'2[-2] = P2[-2] ^ C1[-2] ^ C'1[-2]
                
                0x2 = P2[-2] ^ C1[-2] ^ C'1[-2]
                
                P2[-2] = 0x2 ^ C1[-2] ^ C'1[-2]
"""

P2_second_to_last = xor(0x2, ciphertext[DES.block_size - 2], c[DES.block_size - 2])

assert P2_second_to_last == padded_plaintext[-2]

###########################################
###            S T E P   1 1            ###
###########################################

"""
We get the drill. Let's transform Steps 7 - 11 into a loop, to extract the entire P2 block.
"""

c = bytearray(ZEROS_BLOCK + ciphertext[DES.block_size :])


for i in range(1, DES.block_size + 1):
    
    # make the last `i - 1` bytes decipher into the number `i`
    for j in range(1, i):
        c[DES.block_size - j] ^= (i - 1) ^ i

    # make the last `i` byte decipher into the number `i`
    while not oracle(c):
        c[DES.block_size - i] += 1


    P2_i = xor(i, ciphertext[DES.block_size - i], c[DES.block_size - i])

    assert P2_i == padded_plaintext[-i]


###########################################
###            S T E P   1 2            ###
###########################################

"""
In Step 11 we disclosed P2, which is the 2nd block of the padded plaintext.
Now, let's write code to reveal the entire padded plaintext!
"""

def disclose_block(ciphertext, iv, block_idx):
    
    curr_block = ciphertext[block_idx * DES.block_size : (block_idx + 1) * DES.block_size]
        
    prev_block = (
        ciphertext[(block_idx - 1) * DES.block_size : block_idx * DES.block_size]
        if block_idx > 0 else iv
    )

    result = bytearray(ZEROS_BLOCK)
    
    c = bytearray(ZEROS_BLOCK + curr_block)

    for i in range(1, DES.block_size + 1):
        
        # make the last `i - 1` bytes decipher into the number `i`
        for j in range(1, i):
            c[DES.block_size - j] ^= (i - 1) ^ i

        # make the last `i` byte decipher into the number `i`
        while not oracle(c):
            c[DES.block_size - i] += 1

        result[-i] = xor(i, prev_block[-i], c[DES.block_size - i])
        
    return result


def padding_oracle_attack(ciphertext, iv):
    NUM_BLOCKS = len(ciphertext) // DES.block_size
    
    results = [ZEROS_BLOCK] * NUM_BLOCKS
    
    for block_idx in range(NUM_BLOCKS):
        results[block_idx] = disclose_block(ciphertext, iv, block_idx)
        
    return unpad(b''.join(results), DES.block_size)
    

"""
>>> padding_oracle_attack(ciphertext, IV)
>>> b'Hello World'

Our attack is complete.
"""

assert padding_oracle_attack(ciphertext, IV) == plaintext
