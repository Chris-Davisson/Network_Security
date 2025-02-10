#!/usr/bin/env python3
import sys, random
from time import sleep
from scapy.all import sr1, IP, ICMP, TCP

# --------------------------
# Helper: send a SYN packet
# --------------------------
def send_SYN(target_ip: str, spoof: str = None, target_port: int = 80) -> any:
    try:
        if spoof:
            ip_layer = IP(src=spoof, dst=target_ip)
        else:
            ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(
            sport=random.randint(1024, 65535),
            dport=target_port,
            flags="S",
            seq=random.randint(0, 2**32 - 1)
        )
        packet = ip_layer / tcp_layer
        resp = sr1(packet, timeout=2, verbose=0)
        return resp
    except Exception as e:
        print(f"Error sending SYN: {e}")
        return None

# --------------------------
# Helper: send an ICMP packet
# --------------------------
def send_ICMP(target_ip: str, spoof: str = None) -> any:
    try:
        if spoof:
            pkt = IP(src=spoof, dst=target_ip)/ICMP()
        else:
            pkt = IP(dst=target_ip)/ICMP()
        resp = sr1(pkt, timeout=2, verbose=0)
        return resp
    except Exception as e:
        print(f"Error sending ICMP: {e}")
        return None

# --------------------------
# Helper: get a list of IP IDs using SYN (or ICMP)
# --------------------------
def get_ids(target_ip: str, count=5, delay=0.5, spoof: str = None, use_syn=True) -> list:
    ids = []
    for i in range(count):
        if use_syn:
            resp = send_SYN(target_ip, spoof=spoof)
        else:
            resp = send_ICMP(target_ip, spoof=spoof)
        if resp and IP in resp:
            ids.append(resp[IP].id)
        else:
            ids.append(None)
        sleep(delay)
    return ids

# --------------------------
# Test 1: Global Counter Test
# (Expect a nearly sequential list for a global counter.)
# --------------------------
def test_global(target_ip: str):
    ids = get_ids(target_ip, count=5, delay=0.2, use_syn=True)
    print("Global Counter Test (no spoofing):")
    print("IP IDs:", ids)
    # Calculate differences modulo 2^16
    diffs = []
    for i in range(len(ids) - 1):
        if ids[i] is not None and ids[i+1] is not None:
            diffs.append((ids[i+1] - ids[i]) % 65536)
    print("Differences:", diffs)
    return ids, diffs

# --------------------------
# Test 2: Per-Destination / Per-Bucket Test
# (Send normal packet vs. spoofed-source packet.)
# --------------------------
def test_per_destination(target_ip: str):
    ids_normal = get_ids(target_ip, count=3, delay=0.2, spoof=None, use_syn=True)
    # Use an arbitrary spoofed source IP (must be in dotted notation)
    ids_spoof = get_ids(target_ip, count=3, delay=0.2, spoof="1.2.3.4", use_syn=True)
    print("\nPer-Destination / Bucket Test:")
    print("Normal (real source) IP IDs:", ids_normal)
    print("Spoofed (src=1.2.3.4) IP IDs:", ids_spoof)
    if ids_normal and ids_spoof and ids_normal[-1] is not None and ids_spoof[0] is not None:
        diff = (ids_spoof[0] - ids_normal[-1]) % 65536
        print("Difference between last normal and first spoofed:", diff)
    return ids_normal, ids_spoof

# --------------------------
# Test 3: Per-Bucket Timing Test
# (Send burst, sleep, then send another burst.)
# --------------------------
def test_per_bucket(target_ip: str):
    burst1 = get_ids(target_ip, count=5, delay=0.1, use_syn=True)
    sleep(5)  # long sleep to force bucket change
    burst2 = get_ids(target_ip, count=5, delay=0.1, use_syn=True)
    print("\nPer-Bucket Timing Test:")
    print("Burst 1 IP IDs:", burst1)
    print("Burst 2 IP IDs:", burst2)
    if burst1 and burst2 and burst1[-1] is not None and burst2[0] is not None:
        jump = (burst2[0] - burst1[-1]) % 65536
        print("Jump between bursts:", jump)
    return burst1, burst2

# --------------------------
# Test 4: Randomization Test
# (Send many packets quickly to check variability.)
# --------------------------
def test_random(target_ip: str):
    ids = get_ids(target_ip, count=20, delay=0.1, use_syn=True)
    print("\nRandomization Test:")
    print("IP IDs:", ids)
    diffs = []
    for i in range(len(ids) - 1):
        if ids[i] is not None and ids[i+1] is not None:
            diffs.append((ids[i+1] - ids[i]) % 65536)
    print("Differences:", diffs)
    return ids, diffs

# --------------------------
# OS Guessing Logic:
#
# - If Test 1 (global) shows nearly constant, small differences (e.g., 1 or 2),
#   that indicates a single global counter. (BSD family, including macOS, FreeBSD, NetBSD.)
#
# - If Test 2 (per-destination) shows that spoofed packets’ IP IDs do not follow the
#   same sequence as real ones (i.e. a large jump between the last real and first spoofed),
#   that suggests a per-destination (or per-bucket) method (typical of Windows).
#
# - If Test 3 (timing test) shows a large jump after a sleep, that is also indicative
#   of a bucketed (time-based) counter, as in Windows.
#
# - If Test 4 shows widely varying (random) values, that is characteristic of Linux
#   randomizing the IP ID for nonfragmentable packets.
#
# For example, you might deduce:
#
#   - Windows: Test 2 and Test 3 reveal discontinuities (per-destination/bucket).
#   - macOS/FreeBSD/NetBSD (BSD-based): Test 1 yields a strictly increasing (global) counter.
#   - Ubuntu (Linux): Test 4 yields high variability (randomized IP IDs) when DF is set.
# --------------------------
def guess_os(target_ip: str):
    print("\n--- Running OS Fingerprinting Tests ---")
    ids_global, diffs_global = test_global(target_ip)
    ids_norm, ids_spoof = test_per_destination(target_ip)
    burst1, burst2 = test_per_bucket(target_ip)
    ids_rand, diffs_rand = test_random(target_ip)

    # Heuristic analysis: (Improved)
    global_consistent = all(diff < 5 for diff in diffs_global) if diffs_global else False
    spoof_jump = False
    if ids_norm and ids_spoof and ids_norm[-1] is not None and ids_spoof[0] is not None:
        spoof_jump = ((ids_spoof[0] - ids_norm[-1]) % 65536) > 100
    bucket_jump = False
    if burst1 and burst2 and burst1[-1] is not None and burst2[0] is not None:
        bucket_jump = ((burst2[0] - burst1[-1]) % 65536) > 100

    # Use standard deviation for randomness check, as in the improved example
    valid_ids_rand = [id for id in ids_rand if id is not None]
    diffs = []
    for i in range(len(valid_ids_rand) - 1):
        diffs.append((valid_ids_rand[i+1] - valid_ids_rand[i]) % 65536)
    std_dev_rand = np.std(diffs) if diffs else 0


    print("\n--- Heuristic Summary ---")
    print("Global test shows sequential (global counter)?", global_consistent)
    print("Spoofed test shows a jump (per-destination/bucket)?", spoof_jump)
    print("Timing test shows a jump (per-bucket)?", bucket_jump)
    print("Random test standard deviation:", std_dev_rand)  # Use std dev

    # Make a guess: (Improved)
    if not global_consistent and std_dev_rand > 5000:
        guess = "Linux (randomized IP ID for nonfragmented packets)"
    elif spoof_jump or bucket_jump or (not global_consistent and std_dev_rand < 1000):  # Key change here
        guess = "Windows or macOS (per-destination / per-bucket method)" # Corrected guess
    elif global_consistent:
        guess = "BSD-based (FreeBSD, NetBSD, or OpenBSD) using a global counter"  # No longer includes macOS
    else:
        guess = "Undetermined"

    print(f"\n[Guess] The target appears to be: {guess}")
    return guess

# --------------------------
# Main entry point
# --------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python os_fingerprint.py <target_ip>")
        sys.exit(1)
    target_ip = sys.argv[1]
    guess_os(target_ip)

if __name__ == "__main__":
    main()
