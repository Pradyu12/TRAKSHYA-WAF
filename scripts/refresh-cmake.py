#!/usr/bin/env python3
"""Regenerate stale CMake artifacts after project rebrand/path changes."""
import os
import shutil
import subprocess
import sys

CMAKE_MIN_VERSION = (3, 20)


def check_cmake_version():
    try:
        out = subprocess.check_output(["cmake", "--version"], text=True)
        version = out.strip().splitlines()[0].split()[-1]
        parts = tuple(int(p) for p in version.split(".")[:2] if p.isdigit())
        if parts < CMAKE_MIN_VERSION:
            raise SystemExit(f"CMake >= {'.'.join(map(str, CMAKE_MIN_VERSION))} required, got {version}")
    except FileNotFoundError:
        raise SystemExit("cmake not found")


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    c_dir = os.path.join(repo_root, "c")
    build_dir = os.path.join(c_dir, "build")
    target = "trakshya-systemd"

    check_cmake_version()

    if os.path.exists(build_dir):
        print(f"Removing stale build dir: {build_dir}")
        shutil.rmtree(build_dir)

    os.makedirs(build_dir, exist_ok=True)

    print("Running cmake configure...")
    subprocess.run(["cmake", "..", "-DCMAKE_BUILD_TYPE=Release"], cwd=build_dir, check=True)

    print("Building C components...")
    subprocess.run(["make", "-j", str(os.cpu_count() or 2)], cwd=build_dir, check=True)

    binary = os.path.join(build_dir, target)
    if not os.path.exists(binary):
        raise SystemExit(f"Build failed: {binary} not found")

    print(f"Built: {binary}")


if __name__ == "__main__":
    main()
