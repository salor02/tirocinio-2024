from scapy.all import rdpcap, wrpcap
from os import path

FILENAME = 'both-same-capture.pcapng'

if __name__ == '__main__':
    pkts = rdpcap(path.join('.', FILENAME))

    filtered = list(pkts[0])

    for idx in range(1, len(pkts)):
        if abs(pkts[idx].time - pkts[idx-1].time) >= 2:
            filtered.append(pkts[idx])

    print(f'Different packages number: {len(filtered)}')
