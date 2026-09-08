import ctypes
import math
import os
import sys
import time
from dataclasses import dataclass, field
from statistics import mean

_EXACT_SAMPLE_LIMIT = 4096
_HISTOGRAM_BUCKETS = 2048
_HISTOGRAM_SCALE = 128


@dataclass
class BoundedLatencyHistogram:
    count: int = 0
    total: float = 0.0
    maximum: float = 0.0
    _samples: list[float] = field(default_factory=list)
    _buckets: list[int] | None = None

    @property
    def retained_values(self) -> int:
        return len(self._samples) + (len(self._buckets) if self._buckets else 0)

    def record(self, value: float) -> None:
        value = max(0.0, float(value))
        self.count += 1
        self.total += value
        self.maximum = max(self.maximum, value)
        if self._buckets is None and len(self._samples) < _EXACT_SAMPLE_LIMIT:
            self._samples.append(value)
            return
        if self._buckets is None:
            self._buckets = [0] * _HISTOGRAM_BUCKETS
            for sample in self._samples:
                self._buckets[self._bucket_index(sample)] += 1
            self._samples.clear()
        self._buckets[self._bucket_index(value)] += 1

    def merge(self, other: BoundedLatencyHistogram) -> None:
        if other.count == 0:
            return
        combined_samples = len(self._samples) + len(other._samples)
        if (
            self._buckets is None
            and other._buckets is None
            and combined_samples <= _EXACT_SAMPLE_LIMIT
        ):
            self._samples.extend(other._samples)
        else:
            self._ensure_buckets()
            if other._buckets is None:
                for sample in other._samples:
                    self._buckets[self._bucket_index(sample)] += 1
            else:
                for index, count in enumerate(other._buckets):
                    self._buckets[index] += count
        self.count += other.count
        self.total += other.total
        self.maximum = max(self.maximum, other.maximum)

    def percentile(self, fraction: float) -> float:
        if self.count == 0:
            return 0.0
        if self._buckets is None:
            ordered = sorted(self._samples)
            index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
            return ordered[index]
        rank = max(1, math.ceil(self.count * fraction))
        cumulative = 0
        for index, count in enumerate(self._buckets):
            cumulative += count
            if cumulative >= rank:
                return min(self.maximum, math.expm1((index + 1) / _HISTOGRAM_SCALE))
        return self.maximum

    def summary(self) -> dict[str, float]:
        return {
            "avg": round(self.total / self.count, 3) if self.count else 0,
            "p50": round(self.percentile(0.50), 3),
            "p95": round(self.percentile(0.95), 3),
            "p99": round(self.percentile(0.99), 3),
            "max": round(self.maximum, 3),
        }

    def _bucket_index(self, value: float) -> int:
        return min(
            _HISTOGRAM_BUCKETS - 1,
            int(math.log1p(value) * _HISTOGRAM_SCALE),
        )

    def _ensure_buckets(self) -> None:
        if self._buckets is not None:
            return
        self._buckets = [0] * _HISTOGRAM_BUCKETS
        for sample in self._samples:
            self._buckets[self._bucket_index(sample)] += 1
        self._samples.clear()


def classify_error(error: BaseException | str) -> tuple[str, str]:
    if isinstance(error, BaseException):
        detail = error.__class__.__name__
        if isinstance(error, TimeoutError):
            return "timeout", detail
        if isinstance(error, ConnectionError):
            return "transport", detail
        return "exception", detail
    detail = str(error)
    if detail.startswith("code_"):
        return "protocol", detail
    if detail.startswith("invalid_"):
        return "contract", detail
    return "scenario", detail


@dataclass
class SampleStats:
    latency: BoundedLatencyHistogram = field(default_factory=BoundedLatencyHistogram)
    errors: dict[str, int] = field(default_factory=dict)
    error_categories: dict[str, int] = field(default_factory=dict)
    expected_rejections: dict[str, int] = field(default_factory=dict)
    requests: int = 0
    successes: int = 0
    transferred_bytes: int = 0

    def record_success(self, latency_ms: float, *, transferred_bytes: int = 0) -> None:
        self.requests += 1
        self.successes += 1
        self.transferred_bytes += transferred_bytes
        self.latency.record(latency_ms)

    def record_error(
        self, error: BaseException | str, latency_ms: float | None
    ) -> None:
        self.requests += 1
        category, detail = classify_error(error)
        self.errors[detail] = self.errors.get(detail, 0) + 1
        self.error_categories[category] = self.error_categories.get(category, 0) + 1
        if latency_ms is not None:
            self.latency.record(latency_ms)

    def record_expected_rejection(self, key: str, latency_ms: float) -> None:
        self.requests += 1
        self.expected_rejections[key] = self.expected_rejections.get(key, 0) + 1
        self.latency.record(latency_ms)

    def merge(self, other: SampleStats) -> None:
        self.latency.merge(other.latency)
        self.requests += other.requests
        self.successes += other.successes
        self.transferred_bytes += other.transferred_bytes
        for target, source in (
            (self.errors, other.errors),
            (self.error_categories, other.error_categories),
            (self.expected_rejections, other.expected_rejections),
        ):
            for key, value in source.items():
                target[key] = target.get(key, 0) + value


@dataclass
class LoadStats:
    total: SampleStats = field(default_factory=SampleStats)
    actions: dict[str, SampleStats] = field(default_factory=dict)
    dropped_iterations: int = 0

    def record_success(
        self,
        action: str,
        latency_ms: float,
        *,
        include_in_total: bool = True,
        transferred_bytes: int = 0,
    ) -> None:
        self.actions.setdefault(action, SampleStats()).record_success(
            latency_ms, transferred_bytes=transferred_bytes
        )
        if include_in_total:
            self.total.record_success(latency_ms, transferred_bytes=transferred_bytes)

    def record_error(
        self,
        action: str,
        error: BaseException | str,
        latency_ms: float | None,
        *,
        include_in_total: bool = True,
    ) -> None:
        self.actions.setdefault(action, SampleStats()).record_error(error, latency_ms)
        if include_in_total:
            self.total.record_error(error, latency_ms)

    def record_expected_rejection(
        self,
        action: str,
        key: str,
        latency_ms: float,
        *,
        include_in_total: bool = True,
    ) -> None:
        self.actions.setdefault(action, SampleStats()).record_expected_rejection(
            key, latency_ms
        )
        if include_in_total:
            self.total.record_expected_rejection(key, latency_ms)

    def record_iteration_success(
        self, latency_ms: float, *, transferred_bytes: int = 0
    ) -> None:
        self.total.record_success(latency_ms, transferred_bytes=transferred_bytes)

    def record_iteration_error(
        self, error: BaseException | str, latency_ms: float | None
    ) -> None:
        self.total.record_error(error, latency_ms)

    def merge(self, other: LoadStats) -> None:
        self.total.merge(other.total)
        self.dropped_iterations += other.dropped_iterations
        for action, action_stats in other.actions.items():
            self.actions.setdefault(action, SampleStats()).merge(action_stats)


def summarize_samples(stats: SampleStats, elapsed: float) -> dict:
    expected_count = sum(stats.expected_rejections.values())
    return {
        "requests": stats.requests,
        "successes": stats.successes,
        "expected_rejection_count": expected_count,
        "expected_rejections": dict(sorted(stats.expected_rejections.items())),
        "errors": dict(sorted(stats.errors.items())),
        "error_categories": dict(sorted(stats.error_categories.items())),
        "success_rate": round(stats.successes / stats.requests, 4)
        if stats.requests
        else 0,
        "valid_outcome_rate": round(
            (stats.successes + expected_count) / stats.requests, 4
        )
        if stats.requests
        else 0,
        "throughput_rps": round(stats.requests / elapsed, 3) if elapsed else 0,
        "latency_ms": stats.latency.summary(),
        "transferred_bytes": stats.transferred_bytes,
        "bytes_per_second": round(stats.transferred_bytes / elapsed, 3)
        if elapsed
        else 0,
    }


@dataclass
class ConnectionStats:
    handshake_latency: BoundedLatencyHistogram = field(
        default_factory=BoundedLatencyHistogram
    )
    attempts: int = 0
    successes: int = 0
    current: int = 0
    peak: int = 0
    expected_rejections: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)

    def connected(self, latency_ms: float) -> None:
        self.attempts += 1
        self.successes += 1
        self.current += 1
        self.peak = max(self.peak, self.current)
        self.handshake_latency.record(latency_ms)

    def failed(self, error: BaseException | str, latency_ms: float) -> None:
        self.attempts += 1
        _, detail = classify_error(error)
        self.errors[detail] = self.errors.get(detail, 0) + 1
        self.handshake_latency.record(latency_ms)

    def rejected(self, key: str, latency_ms: float) -> None:
        self.attempts += 1
        self.expected_rejections[key] = self.expected_rejections.get(key, 0) + 1
        self.handshake_latency.record(latency_ms)

    def disconnected(self) -> None:
        self.current = max(0, self.current - 1)

    def summary(self) -> dict:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "success_rate": round(self.successes / self.attempts, 4)
            if self.attempts
            else 0,
            "handshake_latency_ms": self.handshake_latency.summary(),
            "current_connections": self.current,
            "peak_connections": self.peak,
            "expected_rejections": dict(sorted(self.expected_rejections.items())),
            "errors": dict(sorted(self.errors.items())),
        }


def current_rss_bytes() -> int:
    if os.name == "nt":

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        get_process_memory_info = kernel32.K32GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        get_process_memory_info.restype = ctypes.c_int
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = kernel32.GetCurrentProcess()
        if not get_process_memory_info(process, ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.WorkingSetSize)
    if sys.platform.startswith("linux"):
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            statm = statm_file.read().split()
        return int(statm[1]) * os.sysconf("SC_PAGE_SIZE")
    import resource

    maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum if sys.platform == "darwin" else maximum * 1024)


@dataclass
class GeneratorHealth:
    event_loop_lag: BoundedLatencyHistogram = field(
        default_factory=BoundedLatencyHistogram
    )
    cpu_percent_samples: list[float] = field(default_factory=list)
    rss_samples: list[int] = field(default_factory=list)
    sample_limit: int = 4096

    def record(self, lag_ms: float, cpu_percent: float, rss_bytes: int) -> None:
        self.event_loop_lag.record(lag_ms)
        if len(self.cpu_percent_samples) < self.sample_limit:
            self.cpu_percent_samples.append(cpu_percent)
            self.rss_samples.append(rss_bytes)
        else:
            index = self.event_loop_lag.count % self.sample_limit
            self.cpu_percent_samples[index] = cpu_percent
            self.rss_samples[index] = rss_bytes

    def summary(self) -> dict:
        cpu_peak = max(self.cpu_percent_samples, default=0)
        rss_current = self.rss_samples[-1] if self.rss_samples else current_rss_bytes()
        rss_peak = max(self.rss_samples, default=rss_current)
        lag = self.event_loop_lag.summary()
        saturated = lag["p99"] >= 100 or cpu_peak >= 95
        return {
            "event_loop_lag_ms": lag,
            "cpu_percent_one_core_avg": round(mean(self.cpu_percent_samples), 2)
            if self.cpu_percent_samples
            else 0,
            "cpu_percent_one_core_peak": round(cpu_peak, 2),
            "rss_current_bytes": rss_current,
            "rss_peak_bytes": rss_peak,
            "sample_count": self.event_loop_lag.count,
            "generator_saturated": saturated,
        }


async def monitor_generator(
    stop_event, health: GeneratorHealth, interval: float = 0.25
):
    import asyncio

    last_wall = time.perf_counter()
    last_cpu = time.process_time()
    target = last_wall + interval
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=max(0, target - time.perf_counter()),
            )
        except TimeoutError:
            pass
        else:
            break
        now = time.perf_counter()
        cpu_now = time.process_time()
        wall_delta = now - last_wall
        cpu_percent = (cpu_now - last_cpu) / wall_delta * 100 if wall_delta else 0
        health.record(max(0, now - target) * 1000, cpu_percent, current_rss_bytes())
        last_wall = now
        last_cpu = cpu_now
        target += interval
