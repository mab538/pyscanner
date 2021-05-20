"""
Simple python port scanner
"""

import argparse
import asyncio
import logging
from netaddr import IPNetwork
from queue import Queue
from threading import Thread


handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter(
        style="{",
        fmt="[{name}:{filename}] {levelname} - {message}"
    )
)

log = logging.getLogger("pyscanner")
log.setLevel(logging.INFO)
log.addHandler(handler)

work_queue = Queue()
results = dict()
NUM_THREADS = 4

DEFAULT_PORTS = [80,23,443,21,22,25,3389,110,445,139,143,
    53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,
    199,1720,465,548,113,81,6001,10000,514,5060,179,1026,
    2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,
    49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,
    79,5800,106,2121,1110,49155,6000,513,990,5357,427,
    49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,
    7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,
    49157,1028,873,1755,2717,4899,9100,119,37
]


def expand_ips(ip_or_cidr):
    """
    """
    
    if ',' not in ip_or_cidr:
        ip_or_cidr = [ip_or_cidr]
    else:
        ip_or_cidr = ip_or_cidr.split(',')
    # end if

    ips = []
    for ip in ip_or_cidr:
        for addr in IPNetwork(ip):
            ips.append(str(addr).split("/")[0])
        # end for
    # end for
    return ips
# end expand_ips


def expand_ports(ports):
    if type(ports) == type([]):
        return ports
    # end if

    if ports == "-":
        ports = [x for x in range(0,65535+1)]
    elif "," in ports:
        ports = ports.split(",")
    else:
        ports = [ports]
    # end if

    return ports
# end expand_ports


def scan(q):
    global results

    while True:
        ip, port, protocol = q.get()
        results[ip][protocol]['open'].append(port)
        q.task_done()
    # end while
# end scan


def pprint(results):
    for ip in results:
        print(f'[+] {ip}')
        print("PORT\t\tSTATE")
        for protocol in results[ip].keys():
            for p in results[ip][protocol]['open']:
                print(f"{p}/{protocol}\t\topen")
            # end for
            for p in results[ip][protocol]['closed']:
                print(f"{p}/{protocol}\t\topen")
            # end for
        # end for
    # end for
# end pprint


def main():
    global results

    parser = argparse.ArgumentParser(
        description = "Simple Python Port Scanner"
    )

    parser.add_argument('ip_address_or_cidr_range')

    parser.add_argument(
        '-s', '--syn',
        dest="syn", action="store_true",
        help="SYN Scan (default)",
        default=True
    )

    parser.add_argument(
        '-p', '--port',
        dest="ports",
        action="store",
        help="port(s) to scan"
    )

    parser.add_argument(
        '-t', '--threads',
        dest='threads',
        help="number of scanning threads (default=4)",
        default=4,action="store"
    )

    args = parser.parse_args()
    print(args)

    protocol = 'tcp'

    # process the input
    ips = expand_ips(args.ip_address_or_cidr_range)
    results = {ip: {protocol: {'open': [], 'closed': []}} for ip in ips}
    ports = expand_ports(args.ports or DEFAULT_PORTS)

    # set up the workers
    for i in range(args.threads):
        w = Thread(target=scan, args=(work_queue,))
        w.setDaemon(True)
        w.start()
    # end for

    # populate the threads:
    for ip in ips:
        for port in ports:
            work_queue.put([ip,port, protocol])
        # end for
    # end for
    work_queue.join()
    print('\n[+] Complete.\n')
    pprint(results)

# end main


if __name__ == "__main__":
    main()
