#!/usr/bin/env python3
import subprocess
import re
import time


# It's a giant pain to control the source IP with requests/urllib, so I just use curl
def get(src_ip, url):
    output = subprocess.run(
        ["curl", "--interface", src_ip, "--include", url], capture_output=True
    )
    status_line = output.stdout.decode("utf-8").split("\r\n", 1)[0]
    m = re.match(r"^HTTP/1\.1 (\d+) .*$", status_line)
    assert m
    return int(m.group(1))


def probe_bucket_level(src_ip, url):
    max_tries = 100
    for i in range(max_tries):
        if get(src_ip, url) == 429:
            return i
    return max_tries


def main():
    htcpp = subprocess.Popen(["build/htcpp", "tests/rate_limiting/config.joml"])
    url = "http://localhost:6969/lorem_ipsum.txt"

    print("Testing burst sizes")
    # First request from this IP, bucket should be full (steady_rate)
    assert 10 <= probe_bucket_level("127.0.0.1", url) <= 12
    # Bucket should be empty now, so only 0 or 1 requests should get through
    assert probe_bucket_level("127.0.0.1", url) <= 1

    assert 10 <= probe_bucket_level("127.0.0.2", url) <= 12
    assert 10 <= probe_bucket_level("127.0.0.3", url) <= 12
    assert 10 <= probe_bucket_level("127.0.0.4", url) <= 12
    assert 10 <= probe_bucket_level("127.0.0.5", url) <= 12

    print("Test evictions")
    # 127.0.0.5 should have evicted 127.0.0.1 from the cache and reset rate limiting
    assert 10 <= probe_bucket_level("127.0.0.1", url) <= 12

    print("Test steady rate")
    # Check that steady rate works
    start = time.time()
    num_success = 0
    while time.time() < start + 6.0:
        if get("127.0.0.1", url) == 200:
            num_success += 1
    assert 5 <= num_success <= 6

    print("Stress test evictions")
    # Assert nothing here, just evict a bunch and make sure it doesn't crash or something
    for i in range(255):
        get(f"127.0.0.{i}", url)

    print("Killing htcpp")
    htcpp.kill()
    htcpp.wait()


if __name__ == "__main__":
    main()
