#!/usr/bin/env python3
"""
full_bench.py - Comprehensive Benchmark and Automated Testing Suite for PadBustPy

This module provides:
1. Performance benchmarks for encoding/decoding operations
2. Stress tests for the padding oracle attack simulation
3. End-to-end automated testing against a mock server
4. Memory and timing profiling
5. Report generation

Usage:
    python full_bench.py                     # Run all benchmarks
    python full_bench.py --encoding          # Encoding benchmarks only
    python full_bench.py --attack-sim        # Attack simulation only
    python full_bench.py --e2e               # End-to-end tests only
    python full_bench.py --report            # Generate full HTML report
    python full_bench.py --quick             # Quick validation run
"""

import argparse
import base64
import binascii
import gc
import json
import multiprocessing
import os
import random
import secrets
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import StringIO
from typing import Callable, Dict, List, Optional, Tuple, Any
from urllib.parse import parse_qs, urlparse, quote

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests library not available. Install with: pip install requests")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not available. Install with: pip install cryptography")

# Try to import memory profiler
try:
    import tracemalloc
    TRACEMALLOC_AVAILABLE = True
except ImportError:
    TRACEMALLOC_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

BENCH_CONFIG = {
    "iterations": 1000,
    "warmup_iterations": 100,
    "data_sizes": [16, 64, 256, 1024, 4096],
    "encoding_formats": [0, 1, 2, 3, 4],
    "server_host": "127.0.0.1",
    "server_port": 9998,
    "encryption_key": b"YELLOW SUBMARINE",
    "iv": b"\x00" * 16,
    "block_size": 16,
    "timeout": 60,
    "parallel_workers": 4,
}


# =============================================================================
# Result Data Classes
# =============================================================================

@dataclass
class BenchmarkResult:
    """Result of a single benchmark."""
    name: str
    iterations: int
    total_time: float
    mean_time: float
    std_dev: float
    min_time: float
    max_time: float
    ops_per_second: float
    memory_peak: Optional[int] = None
    passed: bool = True
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "total_time_ms": round(self.total_time * 1000, 3),
            "mean_time_us": round(self.mean_time * 1_000_000, 3),
            "std_dev_us": round(self.std_dev * 1_000_000, 3),
            "min_time_us": round(self.min_time * 1_000_000, 3),
            "max_time_us": round(self.max_time * 1_000_000, 3),
            "ops_per_second": round(self.ops_per_second, 2),
            "memory_peak_kb": round(self.memory_peak / 1024, 2) if self.memory_peak else None,
            "passed": self.passed,
            "error": self.error,
        }


@dataclass
class TestSuiteResult:
    """Result of a test suite run."""
    name: str
    start_time: datetime
    end_time: datetime
    benchmarks: List[BenchmarkResult] = field(default_factory=list)
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    
    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def success_rate(self) -> float:
        total = self.tests_passed + self.tests_failed
        return (self.tests_passed / total * 100) if total > 0 else 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": round(self.duration, 3),
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_skipped": self.tests_skipped,
            "success_rate": round(self.success_rate, 2),
            "benchmarks": [b.to_dict() for b in self.benchmarks],
        }


# =============================================================================
# Utility Functions
# =============================================================================

def web64_encode(data: bytes, net: bool = False) -> str:
    """WebSafe Base64 encoding."""
    encoded = base64.b64encode(data).decode().rstrip('=')
    encoded = encoded.replace('+', '-').replace('/', '_')
    if net:
        count = (4 - len(encoded) % 4) % 4
        encoded += str(count)
    return encoded


def web64_decode(data: str, net: bool = False) -> bytes:
    """WebSafe Base64 decoding."""
    if net:
        count = int(data[-1])
        data = data[:-1]
        data += '=' * count
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)


def encode_decode(data, operation: int, fmt: int):
    """Encode or decode data based on format."""
    if fmt in [1, 2]:
        if operation == 1:
            return binascii.unhexlify(data.lower())
        else:
            if isinstance(data, bytes):
                encoded = binascii.hexlify(data).decode()
            else:
                encoded = binascii.hexlify(data.encode()).decode()
            return encoded.upper() if fmt == 2 else encoded.lower()
    elif fmt == 3:
        if operation == 1:
            return web64_decode(data, net=True)
        else:
            if isinstance(data, str):
                data = data.encode()
            return web64_encode(data, net=True)
    elif fmt == 4:
        if operation == 1:
            return web64_decode(data, net=False)
        else:
            if isinstance(data, str):
                data = data.encode()
            return web64_encode(data, net=False)
    else:
        if operation == 1:
            return base64.b64decode(data)
        else:
            if isinstance(data, bytes):
                return base64.b64encode(data).decode().rstrip('\n')
            else:
                return base64.b64encode(data.encode()).decode().rstrip('\n')


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> Tuple[bytes, bool]:
    """Remove PKCS#7 padding. Returns (data, is_valid)."""
    if not data:
        return data, False
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        return data, False
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            return data, False
    return data[:-pad_len], True


@contextmanager
def timer():
    """Context manager for timing code blocks."""
    start = time.perf_counter()
    times = []
    yield times
    times.append(time.perf_counter() - start)


@contextmanager
def memory_tracker():
    """Context manager for tracking memory usage."""
    if TRACEMALLOC_AVAILABLE:
        gc.collect()
        tracemalloc.start()
        yield
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak
    else:
        yield
        return None


# =============================================================================
# Benchmark Functions
# =============================================================================

class EncodingBenchmarks:
    """Benchmarks for encoding/decoding operations."""
    
    FORMAT_NAMES = {
        0: "Base64",
        1: "Hex (Lower)",
        2: "Hex (Upper)",
        3: ".NET UrlToken",
        4: "WebSafe Base64",
    }
    
    @staticmethod
    def run_encode_benchmark(fmt: int, data_size: int, iterations: int) -> BenchmarkResult:
        """Benchmark encoding operation."""
        data = secrets.token_bytes(data_size)
        times = []
        
        # Warmup
        for _ in range(min(100, iterations // 10)):
            encode_decode(data, 0, fmt)
        
        # Actual benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            encode_decode(data, 0, fmt)
            times.append(time.perf_counter() - start)
        
        return BenchmarkResult(
            name=f"Encode {EncodingBenchmarks.FORMAT_NAMES[fmt]} ({data_size}B)",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
        )
    
    @staticmethod
    def run_decode_benchmark(fmt: int, data_size: int, iterations: int) -> BenchmarkResult:
        """Benchmark decoding operation."""
        data = secrets.token_bytes(data_size)
        encoded = encode_decode(data, 0, fmt)
        times = []
        
        # Warmup
        for _ in range(min(100, iterations // 10)):
            encode_decode(encoded, 1, fmt)
        
        # Actual benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            encode_decode(encoded, 1, fmt)
            times.append(time.perf_counter() - start)
        
        return BenchmarkResult(
            name=f"Decode {EncodingBenchmarks.FORMAT_NAMES[fmt]} ({data_size}B)",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
        )
    
    @staticmethod
    def run_roundtrip_benchmark(fmt: int, data_size: int, iterations: int) -> BenchmarkResult:
        """Benchmark encode-decode roundtrip with verification."""
        data = secrets.token_bytes(data_size)
        times = []
        errors = 0
        
        for _ in range(iterations):
            start = time.perf_counter()
            encoded = encode_decode(data, 0, fmt)
            decoded = encode_decode(encoded, 1, fmt)
            times.append(time.perf_counter() - start)
            if decoded != data:
                errors += 1
        
        result = BenchmarkResult(
            name=f"Roundtrip {EncodingBenchmarks.FORMAT_NAMES[fmt]} ({data_size}B)",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
            passed=errors == 0,
        )
        
        if errors > 0:
            result.error = f"{errors} roundtrip verification failures"
        
        return result


class PaddingBenchmarks:
    """Benchmarks for PKCS#7 padding operations."""
    
    @staticmethod
    def run_pad_benchmark(block_size: int, data_size: int, iterations: int) -> BenchmarkResult:
        """Benchmark padding operation."""
        data = secrets.token_bytes(data_size)
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            pkcs7_pad(data, block_size)
            times.append(time.perf_counter() - start)
        
        return BenchmarkResult(
            name=f"PKCS7 Pad (block={block_size}, data={data_size}B)",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
        )
    
    @staticmethod
    def run_unpad_benchmark(block_size: int, data_size: int, iterations: int) -> BenchmarkResult:
        """Benchmark unpadding operation."""
        data = secrets.token_bytes(data_size)
        padded = pkcs7_pad(data, block_size)
        times = []
        errors = 0
        
        for _ in range(iterations):
            start = time.perf_counter()
            unpadded, valid = pkcs7_unpad(padded)
            times.append(time.perf_counter() - start)
            if not valid or unpadded != data:
                errors += 1
        
        result = BenchmarkResult(
            name=f"PKCS7 Unpad (block={block_size}, data={data_size}B)",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
            passed=errors == 0,
        )
        
        if errors > 0:
            result.error = f"{errors} unpadding verification failures"
        
        return result
    
    @staticmethod
    def run_invalid_padding_detection(iterations: int) -> BenchmarkResult:
        """Benchmark detection of invalid padding."""
        block_size = 16
        times = []
        false_positives = 0
        false_negatives = 0
        
        for i in range(iterations):
            # Create random data with intentionally invalid padding
            data = secrets.token_bytes(block_size - 1) + bytes([random.randint(17, 255)])
            
            start = time.perf_counter()
            _, valid = pkcs7_unpad(data)
            times.append(time.perf_counter() - start)
            
            # Should be invalid (padding byte > block size)
            if valid:
                false_positives += 1
            
            # Also test valid padding
            valid_data = secrets.token_bytes(block_size - 1) + bytes([1])
            _, valid = pkcs7_unpad(valid_data)
            if not valid:
                false_negatives += 1
        
        errors = false_positives + false_negatives
        result = BenchmarkResult(
            name="Invalid Padding Detection",
            iterations=iterations * 2,  # We test both valid and invalid
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=(iterations * 2) / sum(times),
            passed=errors == 0,
        )
        
        if errors > 0:
            result.error = f"FP: {false_positives}, FN: {false_negatives}"
        
        return result


# =============================================================================
# Mock Server for E2E Testing
# =============================================================================

class MockVulnerableServer:
    """Mock server exhibiting padding oracle vulnerability."""
    
    def __init__(self, host: str, port: int, key: bytes, iv: bytes):
        self.host = host
        self.port = port
        self.key = key
        self.iv = iv
        self.server = None
        self.thread = None
        self.running = False
        self.request_count = 0
        self.lock = threading.Lock()
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-CBC."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        padded = pkcs7_pad(plaintext, 16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return self.iv + encryptor.update(padded) + encryptor.finalize()
    
    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bool]:
        """Decrypt ciphertext and return (plaintext, padding_valid)."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        if len(ciphertext) < 32:
            return b'', False
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            decrypted = decryptor.update(ct) + decryptor.finalize()
            return pkcs7_unpad(decrypted)
        except Exception:
            return b'', False
    
    def create_handler(self):
        """Create HTTP request handler."""
        server_instance = self
        
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging
            
            def do_GET(self):
                with server_instance.lock:
                    server_instance.request_count += 1
                
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                
                if 'token' in params:
                    token = params['token'][0]
                    try:
                        ciphertext = base64.b64decode(token)
                        _, valid = server_instance.decrypt(ciphertext)
                        
                        if valid:
                            self.send_response(200)
                            self.send_header('Content-Type', 'text/html')
                            self.end_headers()
                            self.wfile.write(b'Success')
                        else:
                            self.send_response(500)
                            self.send_header('Content-Type', 'text/html')
                            self.end_headers()
                            self.wfile.write(b'Invalid padding')
                    except Exception:
                        self.send_response(400)
                        self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'OK')
            
            def do_POST(self):
                self.do_GET()
        
        return Handler
    
    def start(self):
        """Start server in background thread."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        
        handler = self.create_handler()
        self.server = HTTPServer((self.host, self.port), handler)
        self.running = True
        self.thread = threading.Thread(target=self._serve)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.3)
    
    def _serve(self):
        """Serve requests."""
        while self.running:
            self.server.handle_request()
    
    def stop(self):
        """Stop server."""
        self.running = False
        if self.server:
            self.server.shutdown()
    
    def reset_stats(self):
        """Reset request counter."""
        with self.lock:
            self.request_count = 0


# =============================================================================
# Attack Simulation
# =============================================================================

class AttackSimulator:
    """Simulates padding oracle attack for benchmarking."""
    
    def __init__(self, server: MockVulnerableServer):
        self.server = server
        self.oracle_calls = 0
    
    def oracle(self, ciphertext: bytes) -> bool:
        """Query the padding oracle."""
        self.oracle_calls += 1
        _, valid = self.server.decrypt(ciphertext)
        return valid
    
    def decrypt_byte(self, block: bytes, prev_block: bytes, byte_pos: int, known_intermediate: bytes) -> int:
        """Decrypt a single byte using the padding oracle."""
        block_size = len(block)
        target_padding = block_size - byte_pos
        
        # Build test block
        test_prev = bytearray(block_size)
        
        # Set known intermediate bytes for correct padding
        for i in range(byte_pos + 1, block_size):
            test_prev[i] = known_intermediate[i - byte_pos - 1] ^ target_padding
        
        # Try all possible values
        for guess in range(256):
            test_prev[byte_pos] = guess
            test_ct = self.server.iv + bytes(test_prev) + block
            
            if self.oracle(test_ct):
                # Found valid padding
                intermediate = guess ^ target_padding
                return intermediate
        
        raise ValueError(f"Could not decrypt byte at position {byte_pos}")
    
    def decrypt_block(self, block: bytes, prev_block: bytes) -> bytes:
        """Decrypt a single block."""
        block_size = len(block)
        intermediate = bytearray()
        
        for byte_pos in range(block_size - 1, -1, -1):
            inter_byte = self.decrypt_byte(block, prev_block, byte_pos, bytes(intermediate))
            intermediate.insert(0, inter_byte)
        
        # XOR with previous block to get plaintext
        plaintext = bytes(a ^ b for a, b in zip(intermediate, prev_block))
        return plaintext
    
    def run_simulation(self, plaintext: bytes) -> Tuple[bytes, int, float]:
        """
        Run a complete attack simulation.
        Returns (decrypted_data, oracle_calls, time_elapsed).
        """
        self.oracle_calls = 0
        start_time = time.perf_counter()
        
        ciphertext = self.server.encrypt(plaintext)
        block_size = 16
        
        # Split into blocks (first block is IV)
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        
        decrypted = b''
        for i in range(2, len(blocks)):
            prev_block = blocks[i-1]
            current_block = blocks[i]
            decrypted += self.decrypt_block(current_block, prev_block)
        
        # Also decrypt first data block using IV
        if len(blocks) > 1:
            first_decrypted = self.decrypt_block(blocks[1], blocks[0])
            decrypted = first_decrypted + decrypted
        
        elapsed = time.perf_counter() - start_time
        
        # Remove padding
        unpadded, _ = pkcs7_unpad(decrypted)
        
        return unpadded, self.oracle_calls, elapsed


# =============================================================================
# E2E Test Runner
# =============================================================================

class E2ETestRunner:
    """End-to-end test runner using actual HTTP requests."""
    
    def __init__(self, server: MockVulnerableServer):
        self.server = server
        self.base_url = f"http://{server.host}:{server.port}"
    
    def test_valid_token(self) -> BenchmarkResult:
        """Test that valid tokens are accepted."""
        if not REQUESTS_AVAILABLE:
            return BenchmarkResult(
                name="Valid Token Acceptance",
                iterations=0, total_time=0, mean_time=0, std_dev=0,
                min_time=0, max_time=0, ops_per_second=0,
                passed=False, error="requests library not available"
            )
        
        iterations = 100
        times = []
        errors = 0
        
        plaintext = b"user=admin;role=user"
        ciphertext = self.server.encrypt(plaintext)
        token = base64.b64encode(ciphertext).decode()
        
        for _ in range(iterations):
            start = time.perf_counter()
            resp = requests.get(f"{self.base_url}/?token={quote(token)}", timeout=5)
            times.append(time.perf_counter() - start)
            
            if resp.status_code != 200:
                errors += 1
        
        return BenchmarkResult(
            name="Valid Token Acceptance",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
            passed=errors == 0,
            error=f"{errors} failed requests" if errors > 0 else None,
        )
    
    def test_invalid_padding_detection(self) -> BenchmarkResult:
        """Test that invalid padding is properly rejected."""
        if not REQUESTS_AVAILABLE:
            return BenchmarkResult(
                name="Invalid Padding Rejection",
                iterations=0, total_time=0, mean_time=0, std_dev=0,
                min_time=0, max_time=0, ops_per_second=0,
                passed=False, error="requests library not available"
            )
        
        iterations = 100
        times = []
        errors = 0
        
        plaintext = b"test"
        ciphertext = self.server.encrypt(plaintext)
        
        for _ in range(iterations):
            # Corrupt the last byte
            ct_list = list(ciphertext)
            ct_list[-1] ^= random.randint(1, 255)
            invalid_token = base64.b64encode(bytes(ct_list)).decode()
            
            start = time.perf_counter()
            resp = requests.get(f"{self.base_url}/?token={quote(invalid_token)}", timeout=5)
            times.append(time.perf_counter() - start)
            
            if resp.status_code != 500:
                errors += 1
        
        return BenchmarkResult(
            name="Invalid Padding Rejection",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
            passed=errors == 0,
            error=f"{errors} requests didn't return 500" if errors > 0 else None,
        )
    
    def test_oracle_distinguishability(self) -> BenchmarkResult:
        """Test that valid and invalid responses are distinguishable."""
        if not REQUESTS_AVAILABLE:
            return BenchmarkResult(
                name="Oracle Distinguishability",
                iterations=0, total_time=0, mean_time=0, std_dev=0,
                min_time=0, max_time=0, ops_per_second=0,
                passed=False, error="requests library not available"
            )
        
        iterations = 50
        times = []
        distinguishable_count = 0
        
        plaintext = b"test_data_here"
        ciphertext = self.server.encrypt(plaintext)
        valid_token = base64.b64encode(ciphertext).decode()
        
        for _ in range(iterations):
            # Create invalid token
            ct_list = list(ciphertext)
            ct_list[-1] ^= 0xFF
            invalid_token = base64.b64encode(bytes(ct_list)).decode()
            
            start = time.perf_counter()
            resp_valid = requests.get(f"{self.base_url}/?token={quote(valid_token)}", timeout=5)
            resp_invalid = requests.get(f"{self.base_url}/?token={quote(invalid_token)}", timeout=5)
            times.append(time.perf_counter() - start)
            
            if resp_valid.status_code != resp_invalid.status_code:
                distinguishable_count += 1
        
        return BenchmarkResult(
            name="Oracle Distinguishability",
            iterations=iterations,
            total_time=sum(times),
            mean_time=statistics.mean(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            ops_per_second=iterations / sum(times),
            passed=distinguishable_count == iterations,
            error=f"Only {distinguishable_count}/{iterations} distinguishable" if distinguishable_count != iterations else None,
        )
    
    def test_concurrent_requests(self) -> BenchmarkResult:
        """Test server under concurrent load."""
        if not REQUESTS_AVAILABLE:
            return BenchmarkResult(
                name="Concurrent Request Handling",
                iterations=0, total_time=0, mean_time=0, std_dev=0,
                min_time=0, max_time=0, ops_per_second=0,
                passed=False, error="requests library not available"
            )
        
        iterations = 200
        workers = BENCH_CONFIG["parallel_workers"]
        times = []
        errors = 0
        
        plaintext = b"concurrent_test"
        ciphertext = self.server.encrypt(plaintext)
        token = base64.b64encode(ciphertext).decode()
        
        def make_request():
            try:
                start = time.perf_counter()
                resp = requests.get(f"{self.base_url}/?token={quote(token)}", timeout=5)
                elapsed = time.perf_counter() - start
                return (elapsed, resp.status_code == 200)
            except Exception:
                return (0, False)
        
        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(make_request) for _ in range(iterations)]
            for future in as_completed(futures):
                elapsed, success = future.result()
                times.append(elapsed)
                if not success:
                    errors += 1
        total_time = time.perf_counter() - start_time
        
        return BenchmarkResult(
            name="Concurrent Request Handling",
            iterations=iterations,
            total_time=total_time,
            mean_time=statistics.mean(times) if times else 0,
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times) if times else 0,
            max_time=max(times) if times else 0,
            ops_per_second=iterations / total_time,
            passed=errors == 0,
            error=f"{errors} failed requests" if errors > 0 else None,
        )


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generate benchmark reports."""
    
    @staticmethod
    def generate_text_report(results: TestSuiteResult) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"PadBustPy Benchmark Report")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Suite: {results.name}")
        lines.append(f"Duration: {results.duration:.2f} seconds")
        lines.append(f"Tests Passed: {results.tests_passed}")
        lines.append(f"Tests Failed: {results.tests_failed}")
        lines.append(f"Tests Skipped: {results.tests_skipped}")
        lines.append(f"Success Rate: {results.success_rate:.1f}%")
        lines.append("")
        lines.append("-" * 80)
        lines.append("Benchmark Results")
        lines.append("-" * 80)
        lines.append("")
        
        for bench in results.benchmarks:
            status = "✓ PASS" if bench.passed else "✗ FAIL"
            lines.append(f"{status} {bench.name}")
            lines.append(f"    Iterations: {bench.iterations}")
            lines.append(f"    Mean Time: {bench.mean_time * 1_000_000:.2f} µs")
            lines.append(f"    Std Dev: {bench.std_dev * 1_000_000:.2f} µs")
            lines.append(f"    Ops/sec: {bench.ops_per_second:,.0f}")
            if bench.error:
                lines.append(f"    Error: {bench.error}")
            lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)
    
    @staticmethod
    def generate_html_report(results: TestSuiteResult) -> str:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PadBustPy Benchmark Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-card h3 {{ margin: 0; color: #666; font-size: 14px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; color: #333; }}
        .stat-card.pass .value {{ color: #28a745; }}
        .stat-card.fail .value {{ color: #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .pass {{ color: #28a745; }}
        .fail {{ color: #dc3545; }}
        .error {{ color: #dc3545; font-size: 12px; }}
        .timestamp {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PadBustPy Benchmark Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <div class="stat-card">
                <h3>Duration</h3>
                <div class="value">{results.duration:.1f}s</div>
            </div>
            <div class="stat-card pass">
                <h3>Passed</h3>
                <div class="value">{results.tests_passed}</div>
            </div>
            <div class="stat-card fail">
                <h3>Failed</h3>
                <div class="value">{results.tests_failed}</div>
            </div>
            <div class="stat-card">
                <h3>Success Rate</h3>
                <div class="value">{results.success_rate:.0f}%</div>
            </div>
        </div>
        
        <h2>Benchmark Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Benchmark</th>
                    <th>Iterations</th>
                    <th>Mean Time</th>
                    <th>Std Dev</th>
                    <th>Ops/sec</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for bench in results.benchmarks:
            status_class = "pass" if bench.passed else "fail"
            status_icon = "✓" if bench.passed else "✗"
            error_html = f'<br><span class="error">{bench.error}</span>' if bench.error else ""
            
            html += f"""                <tr>
                    <td class="{status_class}">{status_icon}</td>
                    <td>{bench.name}{error_html}</td>
                    <td>{bench.iterations:,}</td>
                    <td>{bench.mean_time * 1_000_000:.2f} µs</td>
                    <td>{bench.std_dev * 1_000_000:.2f} µs</td>
                    <td>{bench.ops_per_second:,.0f}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def generate_json_report(results: TestSuiteResult) -> str:
        """Generate JSON report."""
        return json.dumps(results.to_dict(), indent=2)


# =============================================================================
# Main Benchmark Runner
# =============================================================================

class BenchmarkRunner:
    """Main benchmark runner."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or BENCH_CONFIG
        self.server: Optional[MockVulnerableServer] = None
        self.results = TestSuiteResult(
            name="PadBustPy Full Benchmark Suite",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
    
    def setup(self):
        """Setup test environment."""
        if CRYPTO_AVAILABLE:
            self.server = MockVulnerableServer(
                self.config["server_host"],
                self.config["server_port"],
                self.config["encryption_key"],
                self.config["iv"],
            )
            self.server.start()
            print(f"Mock server started on {self.config['server_host']}:{self.config['server_port']}")
    
    def teardown(self):
        """Cleanup test environment."""
        if self.server:
            self.server.stop()
            print("Mock server stopped")
    
    def run_encoding_benchmarks(self):
        """Run all encoding benchmarks."""
        print("\n" + "=" * 60)
        print("ENCODING BENCHMARKS")
        print("=" * 60)
        
        iterations = self.config["iterations"]
        
        for fmt in self.config["encoding_formats"]:
            for size in self.config["data_sizes"]:
                # Encode benchmark
                result = EncodingBenchmarks.run_encode_benchmark(fmt, size, iterations)
                self._record_result(result)
                
                # Decode benchmark
                result = EncodingBenchmarks.run_decode_benchmark(fmt, size, iterations)
                self._record_result(result)
        
        # Roundtrip benchmarks
        for fmt in self.config["encoding_formats"]:
            result = EncodingBenchmarks.run_roundtrip_benchmark(fmt, 256, iterations)
            self._record_result(result)
    
    def run_padding_benchmarks(self):
        """Run padding benchmarks."""
        print("\n" + "=" * 60)
        print("PADDING BENCHMARKS")
        print("=" * 60)
        
        iterations = self.config["iterations"]
        block_size = self.config["block_size"]
        
        for size in self.config["data_sizes"]:
            # Pad benchmark
            result = PaddingBenchmarks.run_pad_benchmark(block_size, size, iterations)
            self._record_result(result)
            
            # Unpad benchmark
            result = PaddingBenchmarks.run_unpad_benchmark(block_size, size, iterations)
            self._record_result(result)
        
        # Invalid padding detection
        result = PaddingBenchmarks.run_invalid_padding_detection(iterations)
        self._record_result(result)
    
    def run_attack_simulation(self):
        """Run attack simulation benchmarks."""
        if not CRYPTO_AVAILABLE:
            print("\n[SKIP] Attack simulation requires cryptography library")
            self.results.tests_skipped += 1
            return
        
        print("\n" + "=" * 60)
        print("ATTACK SIMULATION")
        print("=" * 60)
        
        simulator = AttackSimulator(self.server)
        
        test_cases = [
            b"admin",
            b"user=admin;role=user",
            b"A" * 32,
        ]
        
        for plaintext in test_cases:
            try:
                decrypted, calls, elapsed = simulator.run_simulation(plaintext)
                
                passed = decrypted == plaintext
                error = None if passed else f"Decryption mismatch: expected {plaintext!r}, got {decrypted!r}"
                
                result = BenchmarkResult(
                    name=f"Attack Simulation ({len(plaintext)}B plaintext)",
                    iterations=1,
                    total_time=elapsed,
                    mean_time=elapsed,
                    std_dev=0,
                    min_time=elapsed,
                    max_time=elapsed,
                    ops_per_second=1 / elapsed if elapsed > 0 else 0,
                    passed=passed,
                    error=error,
                )
                
                print(f"  Plaintext: {plaintext[:20]}...")
                print(f"  Oracle calls: {calls}")
                print(f"  Time: {elapsed:.2f}s")
                print(f"  Calls/block: {calls / (len(plaintext) // 16 + 1):.0f}")
                print()
                
                self._record_result(result)
            except Exception as e:
                result = BenchmarkResult(
                    name=f"Attack Simulation ({len(plaintext)}B)",
                    iterations=0, total_time=0, mean_time=0, std_dev=0,
                    min_time=0, max_time=0, ops_per_second=0,
                    passed=False, error=str(e)
                )
                self._record_result(result)
    
    def run_e2e_tests(self):
        """Run end-to-end HTTP tests."""
        if not CRYPTO_AVAILABLE or not REQUESTS_AVAILABLE:
            print("\n[SKIP] E2E tests require cryptography and requests libraries")
            self.results.tests_skipped += 1
            return
        
        print("\n" + "=" * 60)
        print("END-TO-END TESTS")
        print("=" * 60)
        
        runner = E2ETestRunner(self.server)
        
        tests = [
            runner.test_valid_token,
            runner.test_invalid_padding_detection,
            runner.test_oracle_distinguishability,
            runner.test_concurrent_requests,
        ]
        
        for test in tests:
            result = test()
            self._record_result(result)
    
    def run_quick_validation(self):
        """Run quick validation tests."""
        print("\n" + "=" * 60)
        print("QUICK VALIDATION")
        print("=" * 60)
        
        # Just run essential tests with fewer iterations
        iterations = 100
        
        # One encoding roundtrip
        result = EncodingBenchmarks.run_roundtrip_benchmark(0, 256, iterations)
        self._record_result(result)
        
        # Padding validation
        result = PaddingBenchmarks.run_invalid_padding_detection(iterations)
        self._record_result(result)
        
        if self.server and REQUESTS_AVAILABLE:
            runner = E2ETestRunner(self.server)
            result = runner.test_valid_token()
            self._record_result(result)
    
    def _record_result(self, result: BenchmarkResult):
        """Record a benchmark result."""
        self.results.benchmarks.append(result)
        
        if result.passed:
            self.results.tests_passed += 1
            status = "✓ PASS"
        else:
            self.results.tests_failed += 1
            status = "✗ FAIL"
        
        print(f"  {status} {result.name}")
        print(f"       Mean: {result.mean_time * 1_000_000:.2f} µs | Ops/sec: {result.ops_per_second:,.0f}")
        if result.error:
            print(f"       Error: {result.error}")
    
    def run_all(self):
        """Run all benchmarks."""
        self.results.start_time = datetime.now()
        
        try:
            self.setup()
            self.run_encoding_benchmarks()
            self.run_padding_benchmarks()
            self.run_attack_simulation()
            self.run_e2e_tests()
        finally:
            self.teardown()
            self.results.end_time = datetime.now()
    
    def print_summary(self):
        """Print summary of results."""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Duration: {self.results.duration:.2f} seconds")
        print(f"Tests Passed: {self.results.tests_passed}")
        print(f"Tests Failed: {self.results.tests_failed}")
        print(f"Tests Skipped: {self.results.tests_skipped}")
        print(f"Success Rate: {self.results.success_rate:.1f}%")


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PadBustPy Benchmark Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('--encoding', action='store_true', help='Run encoding benchmarks only')
    parser.add_argument('--padding', action='store_true', help='Run padding benchmarks only')
    parser.add_argument('--attack-sim', action='store_true', help='Run attack simulation only')
    parser.add_argument('--e2e', action='store_true', help='Run E2E tests only')
    parser.add_argument('--quick', action='store_true', help='Quick validation run')
    parser.add_argument('--report', choices=['text', 'html', 'json'], help='Generate report')
    parser.add_argument('--output', '-o', default='benchmark_report', help='Output file name')
    parser.add_argument('--iterations', '-n', type=int, default=1000, help='Number of iterations')
    parser.add_argument('--port', type=int, default=9998, help='Server port')
    
    args = parser.parse_args()
    
    BENCH_CONFIG["iterations"] = args.iterations
    BENCH_CONFIG["server_port"] = args.port
    
    runner = BenchmarkRunner(BENCH_CONFIG)
    
    try:
        if args.quick:
            runner.setup()
            runner.run_quick_validation()
            runner.teardown()
        elif args.encoding:
            runner.run_encoding_benchmarks()
        elif args.padding:
            runner.run_padding_benchmarks()
        elif args.attack_sim:
            runner.setup()
            runner.run_attack_simulation()
            runner.teardown()
        elif args.e2e:
            runner.setup()
            runner.run_e2e_tests()
            runner.teardown()
        else:
            runner.run_all()
        
        runner.results.end_time = datetime.now()
        runner.print_summary()
        
        # Generate report
        if args.report:
            if args.report == 'text':
                report = ReportGenerator.generate_text_report(runner.results)
                filename = f"{args.output}.txt"
            elif args.report == 'html':
                report = ReportGenerator.generate_html_report(runner.results)
                filename = f"{args.output}.html"
            else:
                report = ReportGenerator.generate_json_report(runner.results)
                filename = f"{args.output}.json"
            
            with open(filename, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {filename}")
        
        # Exit with appropriate code
        sys.exit(0 if runner.results.tests_failed == 0 else 1)
        
    except KeyboardInterrupt:
        print("\nBenchmark interrupted")
        runner.teardown()
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        runner.teardown()
        sys.exit(1)


if __name__ == "__main__":
    main()
