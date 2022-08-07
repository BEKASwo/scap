#!/bin/python3

import socket
from threading import Thread
import os
from queue import Queue
import argparse
import ipaddress
import time


class MyError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f'Error: {self.message}'



socket.setdefaulttimeout(0.25)

default_ports = [
    {'port': 7, 'name': 'echo'},
    {'port': 20, 'name': 'ftp'},
    {'port': 21, 'name': 'ftp'},
    {'port': 22, 'name': 'ssh'},
    {'port': 23, 'name': 'telnet'},
    {'port': 25, 'name': 'smtp'},
    {'port': 53, 'name': 'dns'},
    {'port': 80, 'name': 'http'},
    {'port': 110, 'name': 'pop3'},
    {'port': 443, 'name': 'https'},
    {'port': 445, 'name': 'microsoft-ds'},
    {'port': 1194, 'name': 'openvpn'},
    {'port': 3724, 'name': 'WoW'},
    {'port': 27015, 'name': 'half-life'},
]

def CreateParser():
    parser = argparse.ArgumentParser(
        prog='scap', 
        usage='%(prog)s [options] target',
        description='SCAn Ports',
        epilog='Create for Vzlom Jop'
    )

    parser.add_argument(
        'target',
        action='store',
        help='Ip for scanning (10.1.21.23)'
    )
    parser.add_argument(
        '-p', '--port',
        metavar='<port ranges>',
        action='store',
        default=None,
        help='Port or range ports for scanning (default: 1 - 20 000)'
                +'\nEx: -p 22; -p 10-1400; -p 22,44,66'
    )
    parser.add_argument(
        '--def-port',
        action='store_true',
        help='Scanning popular ports'
    )
    parser.add_argument(
        '-d', '--dead',
        action='store_true',
        help='Scaning dead comp'
    )
    parser.add_argument(
        '-i', '--icmp',
        action='store_true',
        help='Ping comps'
    )

    return parser



def PingTarget(ip: str) -> bool:
    command = 'ping -c 1 -W 1 '
    response = os.popen(command + ip)

    for line in response.readlines():
        if line.count('rtt'):
            return True
            
    return False

def ScanTCPPort(addr: (str, int)) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = sock.connect(addr)
        return True

    except ConnectionRefusedError:
        return False

    except:
        return False

def ThreadCheckTargets(ip_range: Queue, ip_live: Queue) -> None:
    while True:
        ip = ip_range.get()
        if PingTarget(ip):
            ip_live.put(ip)
        ip_range.task_done()

def CheckTargets(ip_range: list) -> list:
    ip_live = []

    ip_queue = Queue()
    ip_queue_live = Queue()
    

    for ip in ip_range:
        ip_queue.put(ip)

    for _ in range(int(len(ip_range) / 2) + 1):
        t = Thread(
            target=ThreadCheckTargets,
            args=(ip_queue, ip_queue_live)
        )
        t.daemon = True
        t.start()

    ip_queue.join()

    while not ip_queue_live.empty():
        ip_live.append(ip_queue_live.get())

    return ip_live

def ParsePort(arg_port: str) -> list:
    ports = []

    if '-' in arg_port:
        tmp = arg_port.split('-')
        try:
            start_port = int(tmp[0])
            end_port = int(tmp[1])
        except:
            raise MyError("invalid port")

        if start_port > end_port:
            raise MyError("invalid port")

        if start_port <= 0 or end_port > 65534:
            raise MyError("invalid port")

        for port in range(start_port, end_port + 1):
            ports.append(port)

    else:
        try:
            ports.append(int(arg_port))
        except:
            raise MyError("invalid port")

    return ports

def ThreadScanTCPPort(addr_range: Queue, addr_open: Queue) -> None:
    while True:
        addr = addr_range.get()
        if ScanTCPPort(addr):
            addr_open.put(addr)
        addr_range.task_done()

def CheckAddrs(ip_range: list, port_range) -> list:
    addr_open = []

    addr_range = Queue()
    for ip in ip_range:
        for port in port_range:
            addr_range.put((ip, port))

    addr_open_range = Queue()

    count_threads = int(len(ip_range) * len(port_range) / 5 + 1)
    for _ in range(count_threads):
        t = Thread(
            target=ThreadScanTCPPort,
            args=(addr_range, addr_open_range, )
        )
        t.daemon = True
        t.start()

    addr_range.join()



    while not addr_open_range.empty():
        addr_open.append(addr_open_range.get())

    return addr_open

def PrintPorts(ports):
    if len(ports) == 0:
        return

    print('PORT\t | SERVICE')
    print('_____________________')

    for port in ports:
        flag = False

        for p in default_ports:
            if port == p['port']:
                print(f'{port}\t | {p["name"]}')
                flag = True
                break

        if not flag:
            print(f'{port}\t | unknow')

    print('_____________________')


#args_port = '20-5000'
#args_target = '192.168.1.0/24'
#args_dead = False
#args_def_port = False
#args_only_ping = False

parser = CreateParser()
args = parser.parse_args()

start_time = time.time()

# -------------------------------------------
# Создание списка ip целей
target_range = []
live_targets = []

try:
    net = list(ipaddress.ip_network(args.target).hosts())
    for ip in net:
        target_range.append(ip.exploded)

except:
    print('Error target')
    exit(0)


# Создание списка портов
ports = []


# Кидаем дефолтные порты
if args.port == None or args.def_port:
    for port in default_ports:
        ports.append(port['port'])


# Кидаем указанные порты
if args.port != None:
    try:
        port_range = ParsePort(args.port)

        for port in port_range:
            if port not in ports:
                ports.append(port)

    except MyError as e:
        print(e)
        exit(0)


# Сканирование работающих узлов
if args.dead:
    live_targets = target_range.copy()

else:
    print('\n--- Сканирование работающийх узлов ---')

    live_targets = CheckTargets(target_range)
    live_targets.sort()
    
    print('Список живых узлов: ')

    for live_target in live_targets:
        print(live_target)
    if len(live_targets) == 0:
        print('НЕТ ДАННЫХ')


# Завершение проги, если нужен только пинг
if args.icmp:
    work_time = time.time() - start_time
    print(f'\nВремя работы программы: {work_time}')
    exit(0)


        

# Сканирование портов
print('\n--- Сканирование портов ---')
open_addr = CheckAddrs(live_targets, ports)

for target in live_targets:
    print(f'\n\nУзел: {target}')
    target_ports = []

    for addr in open_addr:
        if target == addr[0]:
            target_ports.append(addr[1])

    target_ports.sort()
    PrintPorts(target_ports)
    print(f'Кол-во открытых портов: {len(target_ports)}')


work_time = time.time() - start_time
print(f'\nВремя работы программы: {work_time}')