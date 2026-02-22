import argparse
import os
import statistics
import subprocess
import time


def run_once(cmd, env=None):
    t0 = time.perf_counter()
    r = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t1 = time.perf_counter()
    if r.returncode != 0:
        raise RuntimeError(f"nonzero rc={r.returncode}")
    return t1 - t0


def median_of(cmd, n, env=None):
    xs = [run_once(cmd, env=env) for _ in range(n)]
    return statistics.median(xs), xs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--m33mu", default="build/m33mu")
    ap.add_argument("--cpu", default="stm32u585")
    ap.add_argument("--bin", required=True)
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--tb", choices=["0", "1"], default="1", help="1=TB enabled, 0=TB disabled")
    args = ap.parse_args()

    base = [
        args.m33mu,
        "--cpu",
        args.cpu,
        "--expect-bkpt",
        "0x7f",
        "--timeout",
        "20",
        args.bin,
    ]
    env = dict(os.environ)
    if args.tb == "0":
        env["M33MU_DISABLE_TB"] = "1"
    else:
        env.pop("M33MU_DISABLE_TB", None)

    med, xs = median_of(base, args.reps, env=env)
    samples = ["%.6f" % x for x in xs]
    print(f"median {med:.6f}s  samples={samples}")
