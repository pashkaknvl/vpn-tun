import os
import struct
import fcntl
import threading

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001

def CREATE_TUN(name="tuno"):
    """Создание TUN интерфейса"""
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def XOR_ENCRYPT(data, key=0x5A):
    """XOR шифрование/дешифрование"""
    return bytes(b ^ key for b in data)

def TUN2_UDP(tun_fd, udp_sock, remote_addr):
    """Читает из TUN, шлёт в UDP"""
    while True:
        packet = os.read(tun_fd, 2048)
        if not packet:
            break
        enc = XOR_ENCRYPT(packet)
        udp_sock.sendto(enc, remote_addr)

def UDP2TUN(tun_fd, udp_sock):
    """Читает из UDP, шлёт в TUN"""
    while True:
        data, _ = udp_sock.recvfrom(4096)
        dec = XOR_ENCRYPT(data)
        os.write(tun_fd, dec)

def start_tunnel(tun, udp, remote_addr=None):
    """Запуск туннелирования"""
    t1 = threading.Thread(
        target=TUN2_UDP,
        args=(tun, udp, remote_addr) if remote_addr else (tun, udp),
        daemon=True
    )
    t2 = threading.Thread(
        target=UDP2TUN,
        args=(tun, udp),
        daemon=True
    )
    
    t1.start()
    t2.start()
    return t1, t2