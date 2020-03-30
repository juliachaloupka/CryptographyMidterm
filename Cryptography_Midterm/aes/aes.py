#!/usr/bin/env python3
# University of Iowa - Spring 2020
# ECE:5995:0002 Spr2020 Contemp Topics in Elect & Computer Eng
# Cryptography
#
# Julia Chalaypka - Master's Computer Engineering 
#    and 
# Daniel Mitchell - Master's Computer Engineering
#testing

# AES S-Box - Substitution values in hexadecimal notation for 
# input byte (x-row, y-column)
# 
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

# Inverse AES S-box - Substituion values in hexadecimal notation for
# input byte (x-row, y-column)
#
inverse_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# byte substitution layer
# only nonlinear element of AES 
# subsitute bytes from s box in state aer
#
def substitute_bytes(s):
        
    i=0;
    
    while i<4:
        j=0;
        while j<4:
            s[i][j] = s_box[s[i][j]]
            j = j+1
        i = i+1

# byte substitution layer
# reverses the byte subsitution from forward encryption using inverse s-box
# only nonlinear element of AES 
#
def inv_substitute_bytes(s):
            
    i=0;
    
    while i<4:
        j=0;
        while j<4:
            s[i][j] = inverse_s_box[s[i][j]]
            j = j+1
        i = i+1

# ShiftRows transform cyclically
# Purpose is to increase diffusion properties
# First row - no shift
# Second row - one position left shift
# Third row - two positions left shift
# Fourth row - three positions left shift
# 
def shift_rows(s):
  
    swaprow1 = (s[1][1],s[2][1], s[3][1], s[0][1])
    swaprow2 = (s[2][2], s[3][2], s[0][2], s[1][2])
    swaprow3 = (s[3][3], s[0][3], s[1][3], s[2][3])
    
    s[0][1], s[1][1], s[2][1], s[3][1] = swaprow1
    s[0][2], s[1][2], s[2][2], s[3][2] = swaprow2
    s[0][3], s[1][3], s[2][3], s[3][3] = swaprow3

# ShiftRows transform cyclically
# Purpose is to reverse diffusion properties from encryption
# First row - no shift
# Second row - one position right shift
# Third row - two positions right shift
# Fourth row - three positions right shift
# 
def inv_shift_rows(s):
  
    swap_invrow1 = s[3][1], s[0][1], s[1][1], s[2][1]
    swap_invrow2 = s[2][2], s[3][2], s[0][2], s[1][2]
    swap_invrow3 = s[1][3], s[2][3], s[3][3], s[0][3]
    
    s[0][1], s[1][1], s[2][1], s[3][1] = swap_invrow1
    s[0][2], s[1][2], s[2][2], s[3][2] = swap_invrow2
    s[0][3], s[1][3], s[2][3], s[3][3] = swap_invrow3

# A 128-bit round key, or subkey, which has been derived from
# the main key in the key schedule is XORed to the state
#
def add_round_key(s, k):
    i=0;
    
    while i<4:
        j=0;
        while j<4:
            s[i][j] =  s[i][j] ^ k[i][j]
            j = j+1
        i = i+1

# Part of the mix column operations
#
def gmult(a):
    if a & 0x80:
        result = (((a << 1) ^ 0x1B) & 0xFF)
    else:
       result= a<<1   
    return result;

# subroutine of of mix columns
# see mix column below
#TODO
def mix_single_column(a):
    # Mix column operations 
    # source of this is from the section 4.1.2 of the Rijndal design
    init_a = a[0] ^ a[1] ^ a[2] ^ a[3]
    temp_a0 = a[0]
    a[0] = a[0]^ ( init_a ^ gmult(a[0] ^ a[1]))
    a[1] = a[1]^ ( init_a ^ gmult(a[1] ^ a[2]))
    a[2] = a[2]^ ( init_a ^ gmult(a[2] ^ a[3]))
    a[3] = a[3]^ ( init_a ^ gmult(a[3] ^ temp_a0))

# mix column mixes each column of the state matrix 
# the purpose is the major diffusion element of AES
#TODO
def mix_columns(s):
    i = 0;
    while i<4:
        mix_single_column(s[i])
        i = i+1;
        
# mix column mixes each column of the state matrix 
# the purpose is the major diffusion element of AES
#TODO
def inv_mix_columns(s):  
    i = 0;
    while i<4:
        inv_mix_column(s[i])
        i = i+1;

    mix_columns(s)
    
# mix column mixes each column of the state matrix 
# inverse mix column reverses the changes made in the forward encryption operation 
# the purpose is the major diffusion element of AES
#TODO
def inv_mix_column(s):
    # see Sec 4.1.3 in The Design of Rijndael
    u = gmult(gmult(s[0] ^ s[2]))
    v = gmult(gmult(s[1] ^ s[3]))
    s[0] = s[0]^ u
    s[1] = s[1]^ v
    s[2] = s[2]^ u
    s[3] = s[3]^ v

# Comments are needed here as to what r_con is - what is does - how its used
# vvvvvvv
round_constants = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

# this routine conversts a 16-byte array into a 4x4 matrix
# to ease the computational code
#
def bytes2matrix(txt):
  
    """ Converts a 16-byte array into a 4x4 matrix.  """
    lenTxt = len(txt)
    #generate an array using 4 lists for each row 
    matrix = [list(txt[i:i+4]) for i in range(0, lenTxt, 4)]
    return matrix

# this routine conversts a 16-byte array into a 4x4 matrix
# to ease the computational code
#
def bytes2matrix(txt):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    lenTxt = len(txt)
    #generate an array using 4 lists for each row 
    matrix = [list(txt[i:i+4]) for i in range(0, lenTxt, 4)]
    return matrix

# this routine conversts a 4x4 matrix into a 16-byte array
# to ease the computational code
#
def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    byte_arr = bytes(sum(matrix, []))
    return byte_arr

# AES 128bit encryption
# ECB Mode
# No Initialization Vector
# Initializes the object with a given key.
# only need 128 so only need size 16, get rid of array rounds by key size
#
#TODO
class AES:
        
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """

        assert len(master_key) in AES.rounds_by_key_size
        self.numRounds = AES.rounds_by_key_size[len(master_key)]
        # Expand and return list of key matricies for given master key
        self._key_matrices = self._expand_key(master_key)
        self._master_key = master_key
        
    #learned from boppreh : https://github.com/boppreh/aes/blob/master/aes.py   
    # Expand and return list of key matricies for given master key
    #
    def _expand_key(self, master_key):
        #   Initialize round keys with raw key material
        key_matrix = bytes2matrix(master_key)
        iteration_size = 4
        #   Each iteration has exactly as many columns as the key material.      
        iteration_size = len(master_key) // 4
        
        i = 1
        while len(key_matrix) < (self.numRounds + 1) * 4:
            # Copy previous row.
            row = list(key_matrix[-1])

            # Perform schedule_core once every 4th interation/every row 
            if len(key_matrix) % iteration_size == 0:
                # Circular shift.
                row.append(row.pop(0))
                # Map to S-BOX.
                row = [s_box[b] for b in row]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                row[0] = row[0] ^ round_constants[i]
                #print("", round_constants[i])
                i = i + 1
            elif len(master_key) == 32 and len(key_matrix) % iteration_size == 4:
                # Run row through S-box in the fourth iteration when using a
                # 256-bit key.
                row = [s_box[b] for b in row]

            # XOR with equivalent row from previous iteration.

            xor_arr = (i^j for i, j in zip(row,key_matrix[-iteration_size]))
            row = bytes(xor_arr)
            key_matrix.append(row)

        # Group key rows in 4x4 byte matrices.
        return [key_matrix[4*i : 4*(i+1)] for i in range(len(key_matrix) // 4)]
        
    # 16 byte long plaintext encryption
    #
    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16
        plaintext_state = bytes2matrix(plaintext)
        #for the first round 
        add_round_key(plaintext_state, self._key_matrices[0])

        i = 1;
        while i < self.numRounds: 
            ### write "ROUND: " (i) [[newline]]
            ### write [[indented]] "State at start:                   " (plaintext_state) [[newline]]
            substitute_bytes(plaintext_state)
            ### write [[indented]] "State after substitution bytes:   " (plaintext_state) [[newline]]
            shift_rows(plaintext_state)
            ### write [[indented]] "State after shift rows:           " (plaintext_state) [[newline]]
            mix_columns(plaintext_state)
            ### write [[indented]] "State after mix columns:          " (plaintext_state) [[newline]]
            add_round_key(plaintext_state, self._key_matrices[i])
            ### write [[indented]] "Key schedule value                " (self.key_matrices[i]) [[newline]]
            i = i + 1;
        # for the last round
         
        ### write "ROUND 10 "
        ### write [[indented]]     "State at start:                   " (plaintext_state)
        substitute_bytes(plaintext_state)
        ### write [[indented]]     "State after substitution bytes:   " (plaintext_state) [[newline]]   
        shift_rows(plaintext_state)
        ### write [[indented]]     "State after shift rows:           " (plaintext_state) [[newline]]
        add_round_key(plaintext_state, self._key_matrices[-1])
        ### ??? write [[indented]] "Key schedule value                " (self.key_matrices[i]) [[newline]]
        ### write "Output Ciphertext :" (plaintext_state) [[newline]]
        
        return matrix2bytes(plaintext_state)

    # 16 byte long plaintext decryption
    #
    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        cipher_state = bytes2matrix(ciphertext)
        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_substitute_bytes(cipher_state)
        
        i = self.numRounds -1;
        while i > 0:
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_substitute_bytes(cipher_state)
            i = i - 1;

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)
    
    def encrypt_block_with_printing(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16
        print("START ENCRYPT: \n \n")
        print("PLAINTEXT: " + bytes(plaintext).hex())
        print("KEY: " + bytes(self._master_key).hex() + "\n")
        plaintext_state = bytes2matrix(plaintext)
        #for the first round 
        add_round_key(plaintext_state, self._key_matrices[0])
        print("round[ 0].input : " + bytes(plaintext).hex() )
        print("round[ 0].k_sch : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(self._key_matrices[0])))
        print("round[ 1].start : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))
        
        i = 1;
        while i < self.numRounds: 
            substitute_bytes(plaintext_state)
            print("round[ " + str(i) + "].s_box : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))
            shift_rows(plaintext_state)
            print("round[ " + str(i) + "].s_row : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))

            mix_columns(plaintext_state)
            print("round[ " + str(i) + "].m_col : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))

            add_round_key(plaintext_state, self._key_matrices[i]) 
            byte_str = b''.join(map(bytes, self._key_matrices[i]))
            print("round[ "+ str(i) +"].k_sch : " + ''.join('{:02x}'.format(x) for x in byte_str))
            
            
            i = i + 1;
        # for the last round
        print("round[ " + str(i) + "].start : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))

        substitute_bytes(plaintext_state)
        print("round[ "+ str(i) +"].s_box : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))

        shift_rows(plaintext_state)
        print("round[ "+ str(i) + "].s_row : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)))

        add_round_key(plaintext_state, self._key_matrices[-1])
        byte_str = b''.join(map(bytes, self._key_matrices[-1]))
        print("round[ "+ str(i) + "].k_sch : " + ''.join('{:02x}'.format(x) for x in byte_str))
        print("round[ "+ str(i) + "].output : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(plaintext_state)) + "\n \nEND ENCRYPT \n \n")


        return matrix2bytes(plaintext_state)
    
    def decrypt_block_with_printing(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16
        print("START DECRYPT: \n \n")
        print("CIPHERTEXT: " + bytes(ciphertext).hex())
        print("KEY: " + bytes(self._master_key).hex() + "\n")
        
        counter = 1;
        
        cipher_state = bytes2matrix(ciphertext)
        print("round[ 0].iinput : " + bytes(ciphertext).hex() )        
        add_round_key(cipher_state, self._key_matrices[-1])
        byte_str = b''.join(map(bytes, self._key_matrices[-1]))
        print("round[ 0].ik_sch : " + ''.join('{:02x}'.format(x) for x in byte_str))
        print("round[ 1].istart : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))
        inv_shift_rows(cipher_state)
        print("round[ 1].is_row : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))

        inv_substitute_bytes(cipher_state)
        print("round[ 1].is_box : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))

        
        i = self.numRounds -1;
        while i > 0:
            add_round_key(cipher_state, self._key_matrices[i])
            byte_str = b''.join(map(bytes, self._key_matrices[i]))
            print("round[ "+ str(counter) + "].ik_sch : " + ''.join('{:02x}'.format(x) for x in byte_str))
            print("round[ " + str(counter) + "].ik_add : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))
            counter = counter + 1;
            inv_mix_columns(cipher_state)
            print("round[ " + str(counter) + "].istart : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))
            inv_shift_rows(cipher_state)
            print("round[ " + str(counter) + "].is_row : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))
            inv_substitute_bytes(cipher_state)
            print("round[ " + str(counter) + "].is_box : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)))

            i = i - 1;
            
        add_round_key(cipher_state, self._key_matrices[0])
        byte_str = b''.join(map(bytes, self._key_matrices[0]))
        print("round[ "+ str(counter) + "].ik_sch : " + ''.join('{:02x}'.format(x) for x in byte_str))
        print("round[ " + str(counter) + "].ioutput : " + ''.join('{:02x}'.format(x) for x in matrix2bytes(cipher_state)) + "\n \nEND DECRYPT \n \n")
        

        return matrix2bytes(cipher_state)

__all__ = [AES]

if __name__ == '__main__':
    import sys
    write = lambda b: sys.stdout.buffer.write(b)
    read = lambda: sys.stdin.buffer.read()
    

# End of Code
