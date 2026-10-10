import socket


def get_local_ips():
    local_ips = set()

    hostname = socket.gethostname()

    try:
        addresses = socket.getaddrinfo(hostname, None)

        for address in addresses:
            ip = address[4][0]
            local_ips.add(ip)

    except socket.gaierror:
        pass

    local_ips.add("127.0.0.1")
    local_ips.add("::1")

    return local_ips