# BIOAEGIS benchmark methodology

This directory contains measurement tooling, not performance claims.

## Detection efficacy

Detection efficacy must be measured against a documented corpus containing known malicious, potentially unwanted, and benign samples. The corpus should be versioned by hash, and the experiment should report true positives, false negatives, false positives, and true negatives.

A result such as `99% detection` is meaningful only when the sample population, time period, test protocol, and ground truth are published.

## False positives

Use a large benign corpus representative of the intended workload: documents, installers, developer projects, archives, scripts, media, browser downloads, and normal administrative tooling. Report the false-positive count and rate separately from detection efficacy.

Do not tune BIOAEGIS against the evaluation corpus after inspecting the labels; that would invalidate the measurement.

## Performance

The harness measures scanner wall time, file throughput, and byte throughput. A serious endpoint benchmark should additionally record CPU utilization, peak RSS, disk I/O, event-to-detection latency, and impact on representative workloads.

Example:

```bash
python benchmarks/measure.py ./benign-corpus --repeat 5 --output benchmark.json
python benchmarks/measure.py ./benign-corpus --deep --repeat 5 --output benchmark-deep.json
```

The benchmark never executes corpus files.

## External validation

Independent malware-detection testing and an external security audit are intentionally not simulated by repository tests. They require a third-party evaluator, a controlled corpus, documented methodology, and access to the system under test.
