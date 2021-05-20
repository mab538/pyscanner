"""
Simple python port scanner
"""

# IMPORT STANDARD MODULES
import argparse
import asyncio
from datetime import timedelta
import logging
import time


# IMPORT LOCAL MODULES
from netaddr import IPNetwork
from queue import Queue
from threading import Thread
from colorama import Fore, Style
from scapy.all import sr1, IP, ICMP, TCP, send, RandShort, conf


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
PADDING = 15
SYNACK = 0x12
RSTACK = 0x14
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
        status = syn_scan_port(ip, port)
        if status == 'open':
            results[ip][protocol]['open'].append(port)
        else:
            results[ip][protocol]['closed'].append(port)
        # end if
        q.task_done()
    # end while
# end scan


def check_host(ip):
    try:
        ping = sr1(IP(dst=ip)/ICMP(), verbose=0, timeout=1)
        if ping:
            log.info(Fore.GREEN + f"[+] {ip} is up")
            print(Style.RESET_ALL)
            return True
        else:
            log.info(Fore.RED + f"[-] {ip} is unreachable")
            print(Style.RESET_ALL)
            return False
        # end if
    except:
        log.info(Fore.RED + f"[-] {ip} is unreachable")
        print(Style.RESET_ALL)
        return False
    # end try
# end check_host


def syn_scan_port(host, port):
    # disable scapy output
    conf.verb = 0

    srcport = RandShort()
    
    # send a SYN packet and wait for the response
    synack = sr1(IP(dst=host)/TCP(sport=srcport, dport=port, flags="S"))
    resp_flags = synack.getlayer(TCP).flags
    
    # close the connection
    rst = IP(dst=host)/TCP(sport=srcport, dport=port, flags='R')
    send(rst)

    # If the response was a SYNACK, the port is considered open
    # If the response was anything else, the port is considered closed
    if resp_flags == SYNACK:
        return "open"
    else:
        return "closed"
    # end if
# end scan_port


def pprint(results, show_closed=False):
    def _format_for_columns(data, padding=PADDING+7):
        out = ''
        for d in data:
            out += str(d).ljust(padding)
        # end for
        return out+Style.RESET_ALL
    # end _format_for_columns

    for ip in results:
        hasData = False
        for protocol in results[ip].keys():
            if len(results[ip][protocol]['open']) > 0:
                print(f'[+] {ip}')
                print('\t', _format_for_columns(['PORT', 'STATE'],PADDING+2))
                hasData = True
                break
            # end if
        # end for

        if not hasData:
            print(f'[-] {ip}')
        # end if
        
        for protocol in results[ip].keys():
            for p in sorted(results[ip][protocol]['open']):
                print('\t',_format_for_columns([Fore.GREEN + f"{p}/{protocol}", 'open']))
            # end for

            if show_closed:
                for p in sorted(results[ip][protocol]['closed']):
                    print('\t',_format_for_columns([Fore.RED + f"{p}/{protocol}", 'closed']))
                # end for
            # end if
        # end for
    # end for
    print(Style.RESET_ALL)
# end pprint


def main():
    global results
    start_time = time.time()

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
        up = check_host(ip)
        if up:
            for port in ports:
                work_queue.put([ip,port, protocol])
            # end for
        else:
            continue
        # end if
    # end for
    work_queue.join()
    log.info('[+] Complete')
    elapsed = time.time() - start_time
    log.info(f'[*] Scan Took: {timedelta(seconds=elapsed)}')
    print()
    pprint(results)

# end main


if __name__ == "__main__":
    main()
