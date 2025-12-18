# PRD-011: Internal TCP Event Ingester

**Project:** Credo Identity Platform

**Owner:** Core Services

**Status:** Draft v1

**Priority:** P1 (Platform Reliability)

---

## 1. Problem Statement

Credo services emit high volumes of structured identity telemetry (token issuance, session lifecycle, consent decisions, authentication attempts). Today these events are sent via synchronous HTTP calls to a logging endpoint, leading to unnecessary per-request overhead, tight coupling between producers and consumers, reliability issues when downstream systems lag, and higher latency on critical identity flows. A lightweight, persistent-connection ingestion path is needed to handle high-throughput internal telemetry without affecting customer-facing latency.

---

## 2. Goals

### Primary Goals

1. Provide a TCP-based ingestion endpoint for internal Credo components.
2. Support high event throughput with stable latency under load.
3. Implement backpressure so slow downstream sinks do not stall core identity flows.
4. Batch and forward events to a pluggable storage sink (file, Postgres, or a Kafka-like mock).
5. Expose basic observability metrics (ingest rate, queue depth, open connections, drops).

### Secondary Goals

- Provide a clear demonstration of distributed-systems design principles.
- Keep the system modular enough for future replacement with Kafka/S3/Snowflake pipelines.

---

## 3. Out of Scope

- No external clients. The service is strictly internal.
- No customer-visible APIs.
- No need for guaranteed exactly-once semantics.
- No enriched analytics or transformations. Just normalization and batching.

---

## 4. Users & Use Cases

### Internal Producers (Credo Services)

- Auth service
- Token service
- Session manager
- Consent service

**Usage:** Send newline-delimited JSON events over long-lived TCP connections.

### Internal Consumers

- Logging/observability pipelines
- Security analytics / anomaly detection (future)
- Audit log writers

---

## 5. Functional Requirements

### 5.1 TCP Ingestion

- The service MUST listen on a configurable TCP port.
- Support many concurrent producers.
- Accept framed events (newline-delimited JSON strings).
- Each connection is handled by an independent, lightweight goroutine.

### 5.2 Validation

- Basic schema validation: must contain `event_type`, `ts`, and `actor`.
- Invalid events must be counted and optionally dropped.

### 5.3 Backpressure & Queueing

- Ingestion pipeline MUST use a bounded internal channel.
- If the internal queue is full:
  - Option A: block producers (default).
  - Option B: drop events with metrics (configurable).
  - Option C: drop oldest vs drop newest is configurable; metrics emitted per strategy.
- Use an MPSC ring buffer implementation with O(1) enqueue/dequeue; document complexity.
- Queue is drained by a worker pool sized for CPU/network throughput; workers run with `context.Context` and exit cleanly on shutdown after flushing in-flight batches.

### 5.4 Batching

- Events MUST be grouped into batches by either:
  - max batch size
  - max batch interval
- Batches are forwarded to the sink.

### 5.5 Sink Module

Initial implementation options:

- File sink (append-only, rotates daily).
- Postgres sink (simple INSERT batching).
- Mock Kafka sink using a buffered channel + disk segments.

The service MUST allow easy swapping of sink implementations.

### 5.6 Metrics

Expose via HTTP `/metrics`:

- open TCP connections
- ingest rate (events/sec)
- queue depth
- dropped events
- batch flush frequency
- sink latency

### 5.7 Secure by Design

- Default deny on malformed frames: unparseable or schema-invalid events are rejected before enqueue and counted.
- Boundary auth: ingester requires mutual auth (mTLS or signed producer token) per connection; unauthenticated connections are dropped immediately.
- Replay protection: producers include monotonic sequence numbers; ingester drops duplicates/out-of-order frames.
- Least privilege: split interfaces `EventAppender` (write-only) vs any reader/debug tooling; sinks run with scoped credentials limited to append/insert.
- Poison handling: batches that repeatedly fail are quarantined with alerts instead of being retried indefinitely.

### 5.8 Sink Persistence (SQL Option)

- Postgres sink uses COPY or batched INSERT with idempotency keys and retries with exponential backoff.
- Hash partitioning on event key and indexes verified via EXPLAIN for hot queries.
- Acceptance requires demonstrating reduced write amplification versus naive single-row inserts.

---

## 6. Non-Functional Requirements

### Performance

- Sustain at least 10k events/sec on a single instance (target for demo).
- Minimal impact on producer services under normal load.

### Reliability

- Service must continue accepting events as long as internal queue is not saturated.
- Batch flushes must be atomic per batch.

### Scalability

- Horizontally scalable by running multiple instances.
- Downstream sinks must be able to handle eventual load (not guaranteed by the ingester).

### Security

- Internal-only.
- Only Credo services can connect (enforced by network policies or shared secret optional).
- Events stored with integrity (no modification).

---

## 7. Architecture Overview

Producers (Auth, Token, Session services) → multiline JSON over TCP → TCP Listener → per-connection goroutine → bounded ingestion queue → batcher → sink module (file/PG/Kafka mock) → metrics & health check.

---

## 8. Success Metrics

- Zero impact on request latency in upstream identity flows after migration.
- Stable performance under 10k events/sec.
- Queue saturation < 5 percent under load tests.
- Easy demonstrability in architecture reviews.

---

## 9. Future Extensions

1. Add protobuf framing instead of JSON.
2. TLS for internal TCP traffic.
3. Real Kafka or Redpanda integration.
4. Per-event routing for different consumers.
5. Replay scripts for debugging production issues.

---

## 10. Acceptance Criteria

- TCP listener accepts concurrent connections and ingests newline-delimited JSON events.
- Events missing `event_type`, `ts`, or `actor` are counted and optionally dropped without crashing producers.
- Backpressure strategy is configurable between blocking producers and dropping events with metrics.
- Batches flush on size or interval thresholds and dispatch through a pluggable sink interface.
- File, Postgres, and mock Kafka sinks are implemented with simple configuration toggles.
- `/metrics` endpoint exposes ingest rate, queue depth, open connections, dropped events, batch flush frequency, and sink latency.
- Load test demonstrates 10k events/sec with <5% queue saturation and no producer-side latency regression.
- Ring buffer and drop-oldest/drop-newest strategies are configurable and covered by metrics.
- # Postgres sink demonstrates idempotent batch persistence with EXPLAIN evidence of partition/index usage.
- Graceful shutdown closes listeners, cancels connection goroutines, and drains the queue without goroutine leaks.

---

## Revision History

| Version | Date       | Author        | Changes                                                                                |
| ------- | ---------- | ------------- | -------------------------------------------------------------------------------------- |
| 1.2     | 2025-12-18 | Security Eng  | Added ring buffer/backpressure strategies and SQL sink (COPY/idempotency) requirements |
| 1.1     | 2025-12-18 | Security Eng  | Added secure-by-design requirements (auth, replay, LP)                                 |
| 1.0     | 2025-12-06 | Core Services | Initial draft                                                                          |
