#![cfg(test)]

use std::time::{Duration, Instant};

pub fn measure(label: &str, iterations: u32, mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    println!(
        "PERF {} iterations={} total_ns={} ns_per_op={:.1}",
        label,
        iterations,
        elapsed.as_nanos(),
        elapsed.as_nanos() as f64 / f64::from(iterations)
    );
    elapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_returns_positive_duration() {
        let elapsed = measure("probe_noop", 1000, || {
            std::hint::black_box(1u32.wrapping_add(1));
        });
        assert!(elapsed.as_nanos() > 0);
    }
}
