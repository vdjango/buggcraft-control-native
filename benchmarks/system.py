"""Bounded local TLS/PostgreSQL ISA comparison. Never targets an existing service."""
import concurrent.futures
import ctypes
import ctypes.util
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("control_integration", ROOT/"tests/integration.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)


def fixture_sql(env, sql):
    """Fixture writes only to the PostgreSQL cluster started by this benchmark."""
    assert env.pg is not None
    library = ctypes.CDLL(ctypes.util.find_library("pq"))
    library.PQconnectdb.argtypes, library.PQconnectdb.restype = [ctypes.c_char_p], ctypes.c_void_p
    library.PQexec.argtypes, library.PQexec.restype = [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_void_p
    library.PQresultStatus.argtypes, library.PQresultStatus.restype = [ctypes.c_void_p], ctypes.c_int
    library.PQclear.argtypes = [ctypes.c_void_p]
    library.PQfinish.argtypes = [ctypes.c_void_p]
    connection = library.PQconnectdb((env.path/"db").read_bytes())
    result = library.PQexec(connection, sql.encode())
    status = library.PQresultStatus(result)
    library.PQclear(result)
    library.PQfinish(connection)
    if status not in (1, 2):
        raise RuntimeError("Benchmark fixture SQL failed")


def proc_usage(pid):
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    ticks = os.sysconf("SC_CLK_TCK")
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    rss = next(int(line.split()[1]) for line in status if line.startswith("VmRSS:"))
    return (int(stat[13])+int(stat[14]))/ticks, rss


def database_cpu(env):
    if not env.pg:
        return None
    total = 0.0
    parent = int((env.pg/"postmaster.pid").read_text().splitlines()[0])
    children = Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
    for pid in [str(parent), *children]:
        try:
            total += proc_usage(int(pid))[0]
        except (OSError, ProcessLookupError):
            pass
    return total


def measure(env, players, operation, body, count=600, concurrency=4):
    port = env.config["port"]
    def worker(arguments):
        player, amount = arguments
        request_body = dict(body)
        if operation == "presence/view":
            request_body["account_id"] = player.account_id
        payload = json.dumps(request_body, separators=(",", ":"))
        connection = None
        latencies, errors, checksum, ciphers = [], 0, 0, set()
        for i in range(amount):
            if connection is None or i % 90 == 0:
                if connection:
                    connection.close()
                connection = http.client.HTTPSConnection("127.0.0.1", port, context=player.context, timeout=15)
            start = time.perf_counter()
            try:
                connection.request("POST", "/v1/"+operation, payload,
                    {"Content-Type": "application/json", "Authorization": "Bearer "+player.token})
                response = connection.getresponse()
                if connection.sock:
                    ciphers.add(tuple(connection.sock.cipher()))
                result = json.loads(response.read())
                if response.status != 200:
                    errors += 1
                elif operation == "placement/candidates":
                    checksum += len(result["candidates"])
                    if len(result["candidates"]) > 8:
                        errors += 1
                else:
                    checksum += int(result.get("state") == "online")
            except Exception:
                errors += 1
                connection.close()
                connection = None
            latencies.append((time.perf_counter()-start)*1000)
        if connection:
            connection.close()
        return latencies, errors, checksum, sorted(ciphers)

    before, _ = proc_usage(env.process.pid)
    db_before = database_cpu(env)
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(worker, [(players[i], count//concurrency) for i in range(concurrency)]))
    elapsed = time.perf_counter()-start
    after, rss = proc_usage(env.process.pid)
    db_after = database_cpu(env)
    latencies = sorted(value for result in results for value in result[0])
    percentile = lambda p: latencies[min(len(latencies)-1, int(p*(len(latencies)-1)))]
    return {"operation": operation, "requests": len(latencies), "seconds": elapsed, "rps": len(latencies)/elapsed,
            "p50_ms": percentile(.5), "p95_ms": percentile(.95), "p99_ms": percentile(.99),
            "errors": sum(r[1] for r in results), "checksum": sum(r[2] for r in results),
            "server_cpu_seconds": after-before, "server_cpu_percent_one_core": (after-before)/elapsed*100,
            "server_rss_kib": rss, "concurrency": concurrency,
            "tls_ciphers": sorted({cipher for result in results for cipher in result[3]}),
            "database_cpu_seconds": None if db_before is None else max(0, db_after-db_before)}


def main():
    output = Path(os.environ.get("CONTROL_BENCHMARK_OUTPUT", ROOT/"validation-artifacts/performance.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"platform": platform.platform(), "cpu": subprocess.check_output(["lscpu"], text=True),
              "openssl": subprocess.check_output(["openssl", "version", "-a"], text=True),
              "compiler": subprocess.check_output(["c++", "--version"], text=True).splitlines()[0],
              "source_sha256": hashlib.sha256(b"".join(p.read_bytes() for p in sorted((ROOT/"src").glob("*.cpp")))).hexdigest(),
              "scope": "Isolated Linux x86-64 cloud VM, loopback TLS + local durable PostgreSQL; not game forwarding or WAN",
              "micro": [], "system": []}
    binary = Path(os.environ["CONTROL_BINARY"]).parent
    report["binary_sha256"] = hashlib.sha256((binary/"buggcraft-control").read_bytes()).hexdigest()
    for round_id in range(5):
        for backend in (["auto", "fallback"] if round_id % 2 == 0 else ["fallback", "auto"]):
            result = json.loads(subprocess.check_output([str(binary/"control-benchmark"), backend, "15000"], text=True))
            report["micro"].append(dict(result, round=round_id+1))
    env = integration.Environment()
    try:
        player, grant, *_ = env.identity()
        player.call("presence/open", {"idempotency_key": "benchmark"})
        fixture_sql(env, """INSERT INTO nodes(id,public_key,credential_id,pool,region,operator,endpoint,epoch,shard,status,slots,bandwidth,health_until)
            SELECT 'n_'||md5(i::text)||md5('id'||i::text),md5('key'||i::text)||md5('key2'||i::text),
            'test','community','synthetic-'||(i%32),'test','203.0.113.1:25565','fixture',i%64,'active',512,1000000000,
            clock_timestamp()+interval '30 minutes' FROM generate_series(1,10000) AS i;
            INSERT INTO identities(id,public_key) SELECT 'fixture-account-'||i::text,'fixture-key-'||i::text FROM generate_series(0,9999) AS i;
            INSERT INTO sessions(id,account_id,device_id,epoch,idem,expires_at)
            SELECT 'fixture-'||i::text,'fixture-account-'||(i%10000),'fixture','fixture',i::text,
            clock_timestamp()+interval '30 minutes' FROM generate_series(1,100000) AS i;""")
        # These are indexed synthetic rows, not 10,000 connected nodes or 100,000 real clients.
        report["synthetic_catalog_nodes"] = 10000
        report["synthetic_session_rows"] = 100000
        for round_id in range(5):
            modes = [("auto", False), ("fallback", False), ("auto", True)]
            if round_id % 2:
                modes.reverse()
            for backend, crypto_off in modes:
                env.process.terminate()
                env.process.wait(timeout=15)
                env.config["json_implementation"] = backend
                integration.write_private(env.path/"config.json", json.dumps(env.config))
                if crypto_off:
                    os.environ["OPENSSL_ia32cap"] = "0:0"
                else:
                    os.environ.pop("OPENSSL_ia32cap", None)
                env.start()
                players = []
                for i in range(4):
                    player, grant, *_ = env.identity()
                    players.append(player)
                    player.call("presence/open", {"idempotency_key": "benchmark"})
                # Refresh a real device session after restart; PostgreSQL remains durable throughout.
                session = player.call("presence/open", {"idempotency_key": f"round-{round_id}-{backend}-{crypto_off}"})
                player.call("presence/refresh", {"session_id": session["session_id"], "sequence": 1})
                for operation, body in (("presence/view", {"account_id": grant["id"]}),
                                        ("placement/candidates", {"region": "synthetic-1", "operator": "test", "nearby": ["synthetic-2"]})):
                    measure(env, players, operation, body, 40)
                    result = measure(env, players, operation, body)
                    result.update({"round": round_id+1, "configured_backend": backend,
                                   "active_backend": env.public.call("health")["json_backend"],
                                   "openssl_cpu_settings": env.public.call("health")["openssl_cpu_settings"],
                                   "openssl_ia32cap": "0:0" if crypto_off else "default"})
                    report["system"].append(result)
                    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
                    print(json.dumps(result), flush=True)
    finally:
        os.environ.pop("OPENSSL_ia32cap", None)
        env.close()
    report["all_error_counts_zero"] = all(row["errors"] == 0 for row in report["system"])
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
