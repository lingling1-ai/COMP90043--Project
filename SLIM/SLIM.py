"""

"""


import random


def encrypt(P, K):
    """
    perform encryption, 32 rounds, P = 32-bit, L=16-bit, R = 16-bit
    The detailed encryption procedure is given in the paper, Figure 2
    :param P: 32-bit long binary string plain text
           K: list of keys(32 16-bit keys)
    :return: C: 32-bit long bin string cipher text
    """
    L = P[:16]
    R = P[16:]
    for i in range(32):
        # 1. Ri XOR Ki
        XORED_R = '{0:0{1}b}'.format(int(R, 2) ^ int(K[i], 2), 16)
        # 2. Substitution: S-box XORed_Ri
        S_XORED_R = S_box(XORED_R)
        # 3. Permutation:
        P_S_XORED_R = P_box(S_XORED_R)
        # 4. P_S_XORED_R XOR Li
        tmp_R = '{0:0{1}b}'.format(int(P_S_XORED_R, 2) ^ int(L, 2), 16)
        # prepare L, R for next round
        L = R
        R = tmp_R
    C = L + R
    return C


def decrypt(C, K):
    """
    Perform decryption, 32 rounds, C = 32-bit, L=16-bit, R=16-bit
    A illustration on decryption is given in the paper, Figure 4
    :param C: 32-bit long binary string cipher text
    :param K: list of keys(32 16-bit keys)
    :return: P: 32-bit long bin string plain text
    """
    L = C[:16]
    R = C[16:]
    for i in range(31, -1, -1):
        # 1. Li XOR Ki
        XORED_L = '{0:0{1}b}'.format(int(L, 2) ^ int(K[i], 2), 16)
        # 2. Substitution: S-box XORed_Ri
        S_XORED_L = S_box(XORED_L)
        # 3. Permutation:
        P_S_XORED_L = P_box(S_XORED_L)
        # 4. P_S_XORED_R XOR Li
        tmp_L = '{0:0{1}b}'.format(int(P_S_XORED_L, 2) ^ int(R, 2), 16)
        # prepare L, R for next round
        R = L
        L = tmp_L
    P = L + R
    return P


def key_generation(MK):
    """
    Performs key generation with a given 80-bit long master key.(32 sub-key generated, each 16-bit long)
    First five keys are sliced from the master key from the LSB to MSB.
    The rest of the keys are taking the 16-bit LSB of the result from each key generation round
    For the details of the key generation process, refer to paper, Figure 3
    :param MK: 80-bit master key binary string.
    :return: list of keys, 32 sub-keys, each 16-bit long.
    """
    key_li = []
    tmp = MK
    # k1 - k5
    key_li.append(tmp[64:])
    key_li.append(tmp[48:64])
    key_li.append(tmp[32:48])
    key_li.append(tmp[16:32])
    key_li.append(tmp[:16])
    # k6 - k32
    key_lsb = tmp[40:]
    key_msb = tmp[:40]
    for i in range(6, 33):
        # 1. keyLSB circular left shift by 2
        key_lsb_head = key_lsb[2:]
        key_lsb_tail = key_lsb[:2]
        key_lsb = key_lsb_head + key_lsb_tail
        # 2. keyLSB XOR KeyMSB
        key_lsb = '{0:0{1}b}'.format(int(key_lsb, 2) ^ int(key_msb, 2),len(key_msb))
        # 3, S-box keyLSB:
        # ***MIGHT PRODUCE VUR: 40 is not divisible by 16 (S-box size is 16), the last chuck is rounded back to LSB
        chuck_1 = key_lsb[24:]
        chuck_2 = key_lsb[8:24]
        chuck_3 = key_lsb[32:] + key_lsb[:8]
        tmp_1 = S_box(chuck_1)
        tmp_2 = S_box(chuck_2)
        tmp_3 = S_box(chuck_3)
        key_lsb = tmp_3[8:] + tmp_2 + tmp_1
        # 4. keyMSB circular left shift by 3
        key_msb_head = key_msb[3:]
        key_msb_tail = key_msb[:3]
        key_msb = key_msb_head + key_msb_tail
        # 5. keyLSB XOR keyMSB
        key_msb = '{0:0{1}b}'.format(int(key_lsb, 2) ^ int(key_msb, 2), len(key_lsb))
        # 6. SLICE the LSB 16-bit to be round key
        key = key_msb[24:]
        key_li.append(key)
    return key_li


def S_box(x):
    """
    Substitution Layer.
    The commented off s_x list is what's given in the paper, but the 0 should be the LSB of the input.
    :param x: the current 16-bit bin data
    :return: the substituted x
    """
    #s_x = {0:12, 1:5, 2:6, 3:11, 4:9, 5:0, 6:10, 7:13, 8:3, 9:14, 10:15, 11:8, 12:4, 13:7, 14:1, 15:2}
    # 0 is the LSB (the most right side)
    s_x = {15: 12, 14: 5, 13: 6, 12: 11, 11: 9, 10: 0, 9: 10, 8: 13, 7: 3, 6: 14, 5: 15, 4: 8, 3: 4, 2: 7, 1: 1, 0: 2}
    res = ""
    for i in range(len(x)):
        res += x[s_x[i]]    # reconstruct from the MSB, most left side
    return res


def P_box(x):
    """
    Permutation Layer.
    The commented off p_x list is what's given in the paper, but the 0 should be the LSB of the input.
    :param x: the current 16-bit bin data
    :return: the new permutation of x
    """
    #p_x = {0:7, 1:13, 2:1, 3:8, 4:11, 5:14, 6:2, 7:5, 8:4, 9:10, 10:15, 11:0, 12:3, 13:6, 14:9, 15:12}
    p_x = {15: 7, 14: 13, 13: 1, 12: 8, 11: 11, 10: 14, 9: 2, 8: 5, 7: 4, 6: 10, 5: 15, 4: 0, 3: 3, 2: 6, 1: 9, 0: 12}
    # 0 is the LSB (the most right side)
    res = ""
    for i in range(len(x)):
        res += x[p_x[i]]
    return res


def verify(C, P, K):
    _P = decrypt(C, K)
    return _P == P, _P


"""Code from Paper's cryptanalysis tool: as reference, not used"""
def _P_box(state):
    """Permutation layer for encryption
    Input:  16-bit integer
    Output: 16-bit integer
    #print(format(state, '016b'))"""
    #print(state)
    state = int(state, 2)
    PBox = [12, 1, 6, 11, 8, 13, 2, 7, 4, 9, 14, 3, 0, 5, 10, 15]
    # PBox = [7, 13, 1, 8, 11, 14, 2, 5, 4, 10, 15, 0, 3, 6, 9, 12]
    output = 0
    for i in range(16):
        output += ((state >> i) & 0x01) << PBox[i]
        # print(format(output, '016b'),format(((state >> i)), '016b'),i,PBox[i])
    #print(output)
    output = bin(output)[2:]
    #print(output)
    return output
import math
def bias(alpha):
    SBox = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1],
            [0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 1, 0, 1, 2, 2],
            [0, 0, 2, 2, 2, 2, 1, 0, 2, 2, 1, 0, 0, 0, 2, 2],
            [0, 0, 2, 2, 2, 2, 0, 1, 2, 2, 0, 1, 0, 0, 2, 2],
            [0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 1, 0, 1, 0, 2, 2],
            [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0],
            [0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
            [0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 1, 1],
            [0, 1, 2, 2, 0, 0, 2, 2, 2, 2, 1, 0, 2, 2, 0, 0],
            [0, 0, 1, 0, 2, 2, 2, 2, 0, 0, 0, 1, 2, 2, 2, 2],
            [0, 1, 0, 0, 2, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2],
            [0, 0, 0, 0, 2, 2, 2, 2, 1, 0, 0, 1, 2, 2, 2, 2],
            [0, 1, 1, 0, 2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 2, 2],
            [0, 0, 2, 2, 1, 1, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0],
            [0, 1, 2, 2, 0, 0, 2, 2, 2, 2, 1, 0, 2, 2, 0, 0]]

    beta = (random.randint(0, 15))
    if (alpha == 0):
        return 0, 0
    else:
        while (SBox[alpha][beta] == 0):
            beta = (random.randint(1, 15))
            # print(SBox[alpha][beta])
        return SBox[alpha][beta], beta
def _S_box(state):
    """SBox function for encryption
    Input:  16-bit integer
    Output: 16-bit integer"""
    sboxcount = 0
    prob = 0
    output = 0
    print(state)
    state = int(state, 2)
    # print('\n')
    for i in range(4):
        inp = (state >> (i * 4)) & 0xF
        if (inp != 0):
            sboxcount = sboxcount + 1
        p, op = bias(inp)
        prob = prob + p
        # print(p,prob)
        output += op << (i * 4)
    output = bin(output)[2:]
    print(output)
    print()
    return output
"""End Code from Paper"""


""" DEBUG """
def debug_prints():
    """
    To debug, manually copy the follow prints commands to your desired position.
    :return: None
    """
    pass
    """
    print(str(k5) == "1001110011100000")
    print(str(k4) == "0010001101100111")
    print(str(k3) == "0111000000101100")
    print(str(k2) == "1000101001010101")
    print(str(k1) == "1001001100100011")
    # k1 1001001100100011
    # k2 1000101001010101
    # k3 0111000000101100
    # k4 0010001101100111
    # k5 1001110011100000
    """
    """
    print("##########ENCRYPTION############")
    print("ROUND ===========================", str(i+1))
        print("L: ", L)
        print("R: ", R)
        print("")
    print(">> step 1 -> R XOR K")
        print("R:", R)
        print("K:", K[i])
        print("XORED_R", XORED_R)
        print("")
    print(">> step 2 -> S-box")
        print("before:", XORED_R)
        print("after:", S_XORED_R)
        print("")
    print(">> step 3 -> P-box")
        print("before:", S_XORED_R)
        print("after:", P_S_XORED_R)
        print("")
    print(">> step 4 -> P_S_XORED_R XOR Li")
        print("R:", P_S_XORED_R)
        print("L:", L)
         print(tmp_R)
        print("")
    print(">> prepare next round")
        print("next L:", L)
        print("next R:", R)
    """
    """
    print("##########DECRYPTION############")
    print("ROUND ===========================", str(-(i-32)))
        print("L: ", L)
        print("R: ", R)
        print("")
    print(">> step 1 -> L XOR K")
        print("L:", L)
        print("K:", K[i])
        print("XORED_L", XORED_L)
        print("")
    print(">> step 2 -> S-box")
        print("before:", XORED_L)
        print("after:", S_XORED_L)
        print("")
    print(">> step 3 -> P-box")
        print("before:", S_XORED_L)
        print("after:", P_S_XORED_L)
        print("")
    print(">> step 4 -> P_S_XORED_L XOR Ri")
        print("L:", P_S_XORED_L)
        print("R:", R)
        print(tmp_L)
        print("")
    print(">> prepare next round")
        print("next L:", L)
        print("next R:", R)
    print("")
    print("To be returned: ", P)
    print("####END DECRYPTION#####")
    print("")
    """


""" TESTS """
def test_1(key_list):
    P = bin(0b10010101000011011111000001101000)[2:]
    C = encrypt(P, key_list)
    #print("")
    Ver, _P = verify(C, P, key_list)
    #print("VERIFY:", Ver)
    #print("")
    #print("Real and Calculated Compare:")
    #print(P)
    #print(_P)
    return Ver


def test_2(key_list):
    P = bin(0b11010101101110111110011101100110)[2:]
    C = encrypt(P, key_list)
    #print("")
    Ver, _P = verify(C, P, key_list)
    #print("VERIFY:", Ver)
    #print("")
    #print("Real and Calculated Compare:")
    #print(P)
    #print(_P)
    return Ver


def test_3(key_list):
    P = bin(0b011001000111010110101011001110011)[2:]
    #print("HERE")
    #print(P)
    C = encrypt(P, key_list)
    #print("")
    Ver, _P = verify(C, P, key_list)
    #print("VERIFY:", Ver)
    #print("")
    #print("Real and Calculated Compare:")
    #print(P)
    #print(_P)
    return Ver


def test_4(key_list):
    P = bin(0b10001001100010111001110011111111)[2:]
    C = encrypt(P, key_list)
    #print("")
    Ver, _P = verify(C, P, key_list)
    #print("VERIFY:", Ver)
    #print("")
    #print("Real and Calculated Compare:")
    #print(P)
    #print(_P)
    return Ver


def test_5(key_list):
    P = bin(0b0010101010101001010000011001101100)[2:]
    C = encrypt(P, key_list)
    #print("")
    Ver, _P = verify(C, P, key_list)
    #print("VERIFY:", Ver)
    #print("")
    #print("Real and Calculated Compare:")
    #print(P)
    #print(_P)
    return Ver


def main():
    # KEY SET 1
    master_key_1 = bin(0b10011100111000000010001101100111011100000010110010001010010101011001001100100011)[2:]
    master_key_2 = bin(0b10100010111000001011000101011101001110011100001110101001011100011110100000111011)[2:]
    master_key_3 = bin(0b00011000111100011100110110010011101000111011110010000110010000100010100000011100)[2:]
    key_list_1 = key_generation(master_key_1)
    key_list_2 = key_generation(master_key_2)
    key_list_3 = key_generation(master_key_3)
    #K = '{0:0{1}b}'.format(random.getrandbits(80), 80)
    #P = '{0:0{1}b}'.format(random.getrandbits(32), 32)

    t1_1 = test_1(key_list_1)
    t1_2 = test_2(key_list_1)
    t1_3 = test_3(key_list_1)
    t1_4 = test_4(key_list_1)
    t1_5 = test_5(key_list_1)
    t2_1 = test_1(key_list_2)
    t2_2 = test_2(key_list_2)
    t2_3 = test_3(key_list_2)
    t2_4 = test_4(key_list_2)
    t2_5 = test_5(key_list_2)
    t3_1 = test_1(key_list_3)
    t3_2 = test_2(key_list_3)
    t3_3 = test_3(key_list_3)
    t3_4 = test_4(key_list_3)
    t3_5 = test_5(key_list_3)

    print("")
    print("========================FINAL RESULT")
    print("TEST WITH KEY SET 1")
    print("Test 1:", t1_1)
    print("Test 2:", t1_2)
    print("Test 3:", t1_3)
    print("Test 4:", t1_4)
    print("Test 5:", t1_5)
    print("TEST WITH KEY SET 2")
    print("Test 1:", t2_1)
    print("Test 2:", t2_2)
    print("Test 3:", t2_3)
    print("Test 4:", t2_4)
    print("Test 5:", t2_5)
    print("TEST WITH KEY SET 3")
    print("Test 1:", t3_1)
    print("Test 2:", t3_2)
    print("Test 3:", t3_3)
    print("Test 4:", t3_4)
    print("Test 5:", t3_5)


if __name__ == "__main__":
    main()
