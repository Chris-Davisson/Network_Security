#!/usr/bin/env python3
import sys, random
from time import sleep
from scapy.all import sr1, IP, ICMP
import numpy as np

# --------------------------
# Helper: send an ICMP packet and get the IP ID
# --------------------------
def get_icmp_ip_id(target_ip: str, df: bool = True, spoof: str = None) -> int | None:
    """
    Sends an ICMP packet to the target and returns the IP ID from the response.

    Args:
        target_ip: The IP address of the target.
        df: Whether to set the Don't Fragment flag.
        spoof: Optional source IP to spoof.

    Returns:
        The IP ID from the response packet, or None if no response was received.
    """
    try:
        if spoof:
            pkt = IP(src=spoof, dst=target_ip, flags="DF" if df else 0) / ICMP()
        else:
            pkt = IP(dst=target_ip, flags="DF" if df else 0) / ICMP()

        resp = sr1(pkt, timeout=2, verbose=0)
        print(repr(resp))  # CRITICAL FOR DEBUG
        if resp and IP in resp:
            return resp[IP].id
        else:
            return None

    except Exception as e:
        print(f"Error sending ICMP packet: {e}")
        return None

# --------------------------
# Basic ICMP IP ID Test Function
# --------------------------
def test_basic_icmp_ipids(target_ip: str):
    """Tests IP ID retrieval for ICMP."""
    print(f"\n--- Basic ICMP IP ID Test for {target_ip} ---")

    print("\nTesting ICMP (DF set):")
    for _ in range(3):  # Send a few packets
        ip_id = get_icmp_ip_id(target_ip, df=True)
        if ip_id is not None:
            print(f"  Received IP ID: {ip_id}")
        else:
            print("  No response or error.")
        sleep(0.5)

    print("\nTesting ICMP (DF not set):")
    for _ in range(3):  # Send a few packets
        ip_id = get_icmp_ip_id(target_ip, df=False)
        if ip_id is not None:
            print(f"  Received IP ID: {ip_id}")
        else:
            print("  No response or error.")
        sleep(0.5)

#----------------------------
# Other Helper Functions
#----------------------------

def get_ids(target_ip: str, count=5, delay=0.5, spoof: str = None, df=True) -> list:
    ids = []
    for i in range(count):
        resp = get_icmp_ip_id(target_ip, spoof=spoof, df=df)
        if resp is not None: #Simplified None check.
            ids.append(resp)
        sleep(delay)
    return ids  # Already filtered for None.

# --- Tests ---

def test_global(target_ip: str):
    ids = get_ids(target_ip, count=5, delay=0.2, df=True)  # ICMP, DF set
    print("Global Counter Test (no spoofing, DF set):")
    print("IP IDs:", ids)
    diffs = [(ids[i + 1] - ids[i]) % 65536 for i in range(len(ids) - 1)] if len(ids) > 1 else []
    print("Differences:", diffs)
    return ids, diffs


def test_per_destination(target_ip: str):
    ids_normal = get_ids(target_ip, count=3, delay=0.2, spoof=None, df=True)  # ICMP, DF set
    ids_spoof = get_ids(target_ip, count=3, delay=0.2, spoof="1.2.3.4", df=True)  # ICMP, DF set
    print("\nPer-Destination / Bucket Test (DF set):")
    print("Normal (real source) IP IDs:", ids_normal)
    print("Spoofed (src=1.2.3.4) IP IDs:", ids_spoof)
    diff = (ids_spoof[0] - ids_normal[-1]) % 65536 if ids_normal and ids_spoof else None
    print("Difference between last normal and first spoofed:", diff)
    return ids_normal, ids_spoof


def test_per_bucket(target_ip: str):
    burst1 = get_ids(target_ip, count=5, delay=0.1, df=True)  # ICMP, DF set
    sleep(5)
    burst2 = get_ids(target_ip, count=5, delay=0.1, df=True)  # ICMP, DF set
    print("\nPer-Bucket Timing Test (DF set):")
    print("Burst 1 IP IDs:", burst1)
    print("Burst 2 IP IDs:", burst2)
    jump = (burst2[0] - burst1[-1]) % 65536 if burst1 and burst2 else None
    print("Jump between bursts:", jump)
    return burst1, burst2


def test_random(target_ip: str):
    ids_df_set = get_ids(target_ip, count=20, delay=0.1, df=True)  # ICMP, DF SET
    ids_df_clear = get_ids(target_ip, count=20, delay=0.1, df=False)  # ICMP, DF CLEAR
    print("\nRandomization Test:")
    print("IP IDs (DF set):", ids_df_set)
    print("IP IDs (DF clear):", ids_df_clear)

    diffs_df_set = [(ids_df_set[i + 1] - ids_df_set[i]) % 65536 for i in range(len(ids_df_set) - 1)] if len(ids_df_set) >1 else []
    diffs_df_clear = [(ids_df_clear[i + 1] - ids_df_clear[i]) % 65536 for i in range(len(ids_df_clear) - 1)] if len(ids_df_clear) > 1 else []

    std_dev_df_set = np.std(diffs_df_set) if diffs_df_set else 0
    std_dev_df_clear = np.std(diffs_df_clear) if diffs_df_clear else 0

    print("Standard Deviation (DF set):", std_dev_df_set)
    print("Standard Deviation (DF clear):", std_dev_df_clear)

    return ids_df_set, std_dev_df_set, ids_df_clear, std_dev_df_clear

# --- OS Guessing Logic ---
def guess_os(target_ip: str):
    print("\n--- Running OS Fingerprinting Tests ---")
    ids_global, diffs_global = test_global(target_ip)
    ids_norm, ids_spoof = test_per_destination(target_ip)
    burst1, burst2 = test_per_bucket(target_ip)
    ids_df_set, std_dev_df_set, ids_df_clear, std_dev_df_clear = test_random(target_ip)

    # Heuristic analysis:
    global_consistent = all(diff < 5 for diff in diffs_global) if diffs_global else False
    spoof_jump = (ids_spoof[0] - ids_norm[-1]) % 65536 > 100 if ids_norm and ids_spoof else False
    bucket_jump = (burst2[0] - burst1[-1]) % 65536 > 100 if burst1 and burst2 else False

    print("\n--- Heuristic Summary ---")
    print("Global test shows sequential (global counter)?", global_consistent)
    print("Spoofed test shows a jump (per-destination/bucket)?", spoof_jump)
    print("Timing test shows a jump (per-bucket)?", bucket_jump)
    print("Random test standard deviation (DF set):", std_dev_df_set)
    print("Random test standard deviation (DF clear):", std_dev_df_clear)

     # Make a guess: (Adapted for ICMP)
    if not global_consistent and std_dev_df_clear > 200:
        guess = "Linux (Possibly randomized IP ID - but less reliable with ICMP)"
    elif spoof_jump or bucket_jump:
        guess = "Windows or macOS (per-destination / per-bucket method)"
    elif global_consistent:
        guess = "BSD-based (FreeBSD, NetBSD, or OpenBSD) using a global counter"
    else:
        guess = "Undetermined"

    print(f"\n[Guess] The target appears to be: {guess}")
    return guess

# --------------------------
# Main entry point
# --------------------------
def main():
    if len(sys.argv) < 2:
        print("<Target_IP> and test if you want to test")
        sys.exit(1)
    target_ip = sys.argv[1]

    if len(sys.argv) > 2 and sys.argv[2].lower() == 'test':
        test_basic_icmp_ipids(target_ip)  # Run the basic ICMP test
    else:
        guess_os(target_ip)  # Run the full fingerprinting


if __name__ == "__main__":
    main()