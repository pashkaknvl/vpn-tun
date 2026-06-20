import socket
import sys

from vpnservice.tunnel import CREATE_TUN, start_tunnel
import vpnservice.auth as auth


def run_client(server_ip="127.0.0.1", port=1194):
    print(f"[CLIENT] Connecting to {server_ip}:{port}")

    action = auth.prompt_action()
    username, password = auth.prompt_credentials()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote_addr = (server_ip, port)
    request = auth.build_request(action, username, password)
    udp.sendto(request, remote_addr)

    response, _ = udp.recvfrom(1024)
    parsed = auth.parse_response(response)

    if parsed is None:
        print("[CLIENT] Invalid server response")
        return

    status, message = parsed
    print(f"[CLIENT] {message}")

    if status != auth.OK:
        return

    tun = CREATE_TUN("tun_client")
    print("[CLIENT] TUN interface created")

    t1, t2 = start_tunnel(tun, udp, remote_addr)
    print("[CLIENT] Tunnel established. Running...")

    try:
        t1.join()
    except KeyboardInterrupt:
        print("\n[CLIENT] Shutting down...")


def main():
    if len(sys.argv) < 2:
        print("Usage: python cli_vpn_client.py <server_ip> [port]")
        print("Example: python cli_vpn_client.py 127.0.0.1 1194")
        sys.exit(1)

    server_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1194
    run_client(server_ip, port)


if __name__ == "__main__":
    main()
