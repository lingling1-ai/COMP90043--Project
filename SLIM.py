import random

# master_key = random.getrandbits(80)



def key_generation():
    key_li = []
    master_key = bin(0b10011100111000000010001101100111011100000010110010001010010101011001001100100011)
    tmp = master_key[2:]
    # k1 - k5
    key_li.append(tmp[64:])
    key_li.append(tmp[48:64])
    key_li.append(tmp[32:48])
    key_li.append(tmp[16:32])
    key_li.append(tmp[:16])
    # k6 - k32
    key_lsb = tmp[40:]
    key_msb = tmp[:40]
    print(len(key_lsb), len(key_msb))



def test():
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


def main():
    key_list = key_generation()


if __name__ == "__main__":
    main()
