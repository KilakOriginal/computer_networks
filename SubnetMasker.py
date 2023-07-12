from math import log2, ceil
from functools import reduce
from sys import argv, exit
import re

def stableSort(toSort: list, reverse: bool = True) -> list:
    '''
    Sort a list and keep original indices. The returned list will be a list of tuples (original_index, value).
    '''
    toSort = [(i, n) for i, n in enumerate(toSort)]
    return sorted(toSort, key=lambda x: x[1], reverse=reverse)

def getSubMasks(cidr: str, subnets: list) -> list:
    '''
    Return a list of subnet masks given a CIDR prefix and a list of the number of hosts in each subnet.
    '''
    try:
        a, b, c, d, x = map(int, re.split(r"[./]", cidr))
    except ValueError:
        print(f"Invalid CIDR address \"{cidr}\". Using default \"0.0.0.0/0\"!")
        a, b, c, d, x = 0, 0, 0, 0, 0

    if 2**(32 - x) < sum(subnets) + len(subnets)*2:
        print("Too many hosts to accomodate in address range!")
        return None

    subnets = stableSort(subnets)   # Calculate subnet masks starting with the largest subnet
    maxAddress = 0  # Highest relative address
    subnetMasks = [None for _ in range(len(subnets))]
    metaMask = reduce(lambda p,q: (p<<8)+q, [a, b, c, d]).to_bytes(4, "big")    # Convert address components to single 32 bit integer
    cidrToString = lambda address, suffix: f"{'.'.join(str(n) for n in [(address >> (8 * (i-1))) & 0xFF for i in range(4, 0, -1)])}/{suffix}" # Convert 32 bit integer and cidr suffix to a.b.c.d/x cidr string
    getBits = lambda x: ceil(log2(x))

    for i, subnet in enumerate(subnets):
        bits = getBits(subnet[1]+2)
        subnetMasks[subnet[0]] = cidrToString(int.from_bytes(metaMask)+maxAddress, 32-bits)
        maxAddress += 2**bits

    return subnetMasks

def main():
    try:
        cidr = argv[1]
        hosts = argv[2:]
    except IndexError:
        print("Usage: <cidr>, <# hosts>*\ne.g.: python SubnetMasker.py 10.245.184.0/23, 98, 23, 30")
        exit()

    print(getSubMasks(cidr, [int(count) for count in hosts]))

if __name__ == "__main__":
    main()
