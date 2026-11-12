#!/usr/bin/env python3
import csv, json, os, subprocess, time
EVE = "/tmp/suri/eve.json"
TRIALS, TIMEOUT, PASS_S = 20, 30, 10
REPLAY = ["ip", "netns", "exec", "attacker", "tcpreplay", "-i", "eth0", "nmap_syn_n.pcap"]

def first_alert(pos, t0):
    with open(EVE) as f:
        f.seek(pos)
        while time.time() - t0 < TIMEOUT:
            line = f.readline()
            if not line:
                time.sleep(0.02); continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") == "alert" and "SCAN" in e["alert"]["signature"].upper():
                return time.time() - t0, e["alert"]["signature"]
    return None, None

with open("results.csv", "w", newline="") as out:
    w = csv.writer(out)
    w.writerow(["trial", "seconds_to_alert", "signature", "passed"])
    passed, times = 0, []
    for i in range(1, TRIALS + 1):
        pos, t0 = os.path.getsize(EVE), time.time()
        subprocess.Popen(REPLAY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        secs, sig = first_alert(pos, t0)
        ok = secs is not None and secs < PASS_S
        passed += ok
        if secs: times.append(secs)
        w.writerow([i, f"{secs:.2f}" if secs else "", sig or "NO ALERT", ok]); out.flush()
        print(f"trial {i:2d}: {secs:.2f} s  {sig}  {'PASS' if ok else 'FAIL'}" if secs else f"trial {i:2d}: NO ALERT  FAIL")
        time.sleep(16)
    print(f"\n>>> {passed}/{TRIALS} trials alerted in under {PASS_S} s (pass mark: 19/20)")
    if times:
        print(f">>> fastest {min(times):.2f} s, slowest {max(times):.2f} s, average {sum(times)/len(times):.2f} s")
