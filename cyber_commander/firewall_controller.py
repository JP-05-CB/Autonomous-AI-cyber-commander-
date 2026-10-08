from bcc import BPF
import socket
import struct
import time
import ctypes as ct 

# ============================================================
# Configuration
# ============================================================

BPF_SOURCE_FILE = "/home/kali/AI_cyber_commander/eBPF.c"

DEVICE = "enp0s8"


# ============================================================
# IP conversion
# ============================================================

def ip_to_u32(ip):

    return struct.unpack(
        "I",
        socket.inet_aton(ip)
    )[0]


def u32_to_ip(value):

    return socket.inet_ntoa(
        struct.pack("I", int(value))
    )


# ============================================================
# Load eBPF
# ============================================================

print("=" * 60)
print("CYBER COMMANDER - eBPF FIREWALL")
print("=" * 60)

print(f"Loading BPF program : {BPF_SOURCE_FILE}")
print(f"Network interface   : {DEVICE}")

b = BPF(src_file=BPF_SOURCE_FILE)

function = b.load_func(
    "xdp_firewall",
    BPF.XDP
)


# ============================================================
# Attach XDP
# ============================================================

print()
print("Attaching XDP firewall...")

b.attach_xdp(
    DEVICE,
    function,
    0
)

print("XDP firewall attached successfully.")


# ============================================================
# Access BPF maps
# ============================================================

blocklist = b["blocklist"]
total_packets = b["total_packets"]


# ============================================================
# Firewall functions
# ============================================================

def block_ip(ip):

    key = ct.c_uint32(ip_to_u32(ip))
    value = ct.c_uint64(0)

    blocklist[key] = value

    print()
    print("🚨 FIREWALL RULE ADDED")
    print("------------------------------")
    print(f"Blocked IP : {ip}")
    print(f"Interface  : {DEVICE}")
    print("Action     : XDP_DROP")
    print("------------------------------")


def unblock_ip(ip):

    key = ct.c_uint32(ip_to_u32(ip))

    try:

        del blocklist[key]

        print()
        print("✅ FIREWALL RULE REMOVED")
        print("------------------------------")
        print(f"Unblocked IP : {ip}")
        print("------------------------------")

    except KeyError:

        print(f"{ip} is not currently blocked.")

# ============================================================
# Show blocklist
# ============================================================

def show_blocklist():

    print()
    print("=" * 60)
    print("ACTIVE BLOCKLIST")
    print("=" * 60)

    if len(blocklist) == 0:

        print("No blocked IP addresses.")

        return

    for key, value in blocklist.items():

        ip = u32_to_ip(key.value)
        dropped = value.value

        print(
            f"{ip:20} "
            f"dropped_packets={dropped}"
        )


# ============================================================
# Interactive controller
# ============================================================

try:

    while True:

        print()
        print("Commands:")
        print("  block <IP>")
        print("  unblock <IP>")
        print("  list")
        print("  stats")
        print("  exit")
        print()

        command = input("firewall> ").strip()

        if command.startswith("block "):

            ip = command.split()[1]

            block_ip(ip)

        elif command.startswith("unblock "):

            ip = command.split()[1]

            unblock_ip(ip)

        elif command == "list":

            show_blocklist()

        elif command == "stats":

            key = 0

            value = total_packets[0]

            print()
            print(
                f"Total IPv4 packets observed: "
                f"{value.value}"
            )

        elif command == "exit":

            break

        else:

            print("Unknown command.")


finally:

    print()
    print("Removing XDP firewall...")

    b.remove_xdp(
        DEVICE,
        0
    )

    print("XDP firewall detached.")
