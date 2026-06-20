import socket
import sys

from core.connection import Database
from vpnservice.tunnel import CREATE_TUN, start_tunnel
import vpnservice.auth as auth


def run_server(port=1194, db_path="db.sqlite"):
    print(f"[SERVER] Starting on 0.0.0.0:{port}")

    db = Database(db_path)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", port))

    client_addr = None
    while client_addr is None:
        print("[SERVER] Waiting for register/login request...")
        data, addr = udp.recvfrom(1024)
        ok, response = auth.handle_auth_packet(db, data)
        udp.sendto(response, addr)

        if ok:
            client_addr = addr
            print(f"[SERVER] Client {addr} authenticated")
        else:
            parsed = auth.parse_response(response)
            message = parsed[1] if parsed else "Authentication failed"
            print(f"[SERVER] Auth error from {addr}: {message}")

    tun = CREATE_TUN("tun_server")
    print("[SERVER] TUN interface created")

    t1, t2 = start_tunnel(tun, udp, client_addr)
    print("[SERVER] Tunnel established. Running...")

    try:
        t1.join()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1194
    db_path = sys.argv[2] if len(sys.argv) > 2 else "db.sqlite"
    run_server(port, db_path)


if __name__ == "__main__":
    main()
