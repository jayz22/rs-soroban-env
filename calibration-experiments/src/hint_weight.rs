//! E4 - ML-DSA `Signature::decode` hint-weight experiment.
//!
//! Throwaway calibration experiment; see `docs/CALIBRATION.md` section 6.4.
//! Not part of the workspace, not intended to be committed.
//!
//! `Signature::decode` performs no cryptography. Its only data-dependent work
//! is `Hint::bit_unpack`, which
//!   1. scans `indices[max_cut..]` for stragglers  -> costs `omega - max_cut`
//!   2. performs `max_cut` bounded writes with strictly-increasing checks
//! The two terms trade off, so the cost is NOT obviously monotonic in hint
//! weight. This experiment measures the direction rather than assuming it.
//!
//! Three parts:
//!   1. distribution of hint weight over honest signatures
//!   2. decode cost as a function of hint weight and layout (crafted)
//!   3. the gap between the honest max and the omega ceiling
//!
//! Signature layout is `c_tilde || z || hint`, where the hint occupies the
//! final `omega + k` bytes: `indices` (omega bytes) then `cuts` (k bytes).
//! `cuts[k-1]` is the cumulative hint weight.

use ml_dsa::{EncodedSignature, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::hint::black_box;

/// Repeats of each decode measurement. Instruction counts are near-noiseless,
/// so this mainly guards against interrupt noise; we report the min.
const REPEATS: usize = 200;

struct Params {
    name: &'static str,
    sig_len: usize,
    omega: usize,
    k: usize,
}

const P44: Params = Params { name: "ML-DSA-44", sig_len: 2420, omega: 80, k: 4 };
const P65: Params = Params { name: "ML-DSA-65", sig_len: 3309, omega: 55, k: 6 };
const P87: Params = Params { name: "ML-DSA-87", sig_len: 4627, omega: 75, k: 8 };

/// Byte offset at which the hint region begins.
fn hint_off(p: &Params) -> usize {
    p.sig_len - (p.omega + p.k)
}

/// Total hint weight of an encoded signature (the last cumulative cut).
fn hint_weight(p: &Params, sig: &[u8]) -> usize {
    sig[p.sig_len - 1] as usize
}

/// Overwrite the hint region of an otherwise honest signature so that the
/// decoded hint has the given per-polynomial cumulative `cuts`. The `z` region
/// is left untouched so the infinity-norm check still passes.
///
/// `bit_unpack` requires: `cuts` non-decreasing, `max_cut <= omega`,
/// `indices[max_cut..]` all zero, and each segment `indices[start..end]`
/// strictly increasing.
fn craft(p: &Params, honest: &[u8], cuts: &[usize]) -> Vec<u8> {
    assert_eq!(cuts.len(), p.k);
    assert!(cuts.windows(2).all(|w| w[0] <= w[1]), "cuts must be non-decreasing");
    let max_cut = *cuts.last().unwrap();
    assert!(max_cut <= p.omega);

    let mut sig = honest.to_vec();
    let off = hint_off(p);
    // indices: each segment 0,1,2,... so it is strictly increasing; tail zeroed.
    let mut start = 0usize;
    for &end in cuts {
        for (n, i) in (start..end).enumerate() {
            sig[off + i] = n as u8;
        }
        start = end;
    }
    for i in max_cut..p.omega {
        sig[off + i] = 0;
    }
    // cuts
    for (j, &c) in cuts.iter().enumerate() {
        sig[off + p.omega + j] = c as u8;
    }
    sig
}

/// Minimum instruction count over REPEATS decodes of `sig`.
fn measure_decode<P: MlDsaParams>(counter: &mut perf_event::Counter, sig: &[u8]) -> u64 {
    let enc: &EncodedSignature<P> = sig.try_into().expect("length");
    // warm up
    for _ in 0..20 {
        black_box(Signature::<P>::decode(black_box(enc)));
    }
    let mut best = u64::MAX;
    for _ in 0..REPEATS {
        counter.reset().unwrap();
        counter.enable().unwrap();
        let r = Signature::<P>::decode(black_box(enc));
        counter.disable().unwrap();
        let c = counter.read().unwrap();
        assert!(black_box(r).is_some(), "crafted signature must decode");
        if c < best {
            best = c;
        }
    }
    best
}

fn honest_sigs<P: MlDsaParams>(rng: &mut StdRng, n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|_| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let sk = SigningKey::<P>::from_seed(&seed.into());
            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut msg);
            sk.expanded_key()
                .sign_deterministic(&msg, &[])
                .expect("sign")
                .encode()
                .to_vec()
        })
        .collect()
}

fn run<P: MlDsaParams>(p: &Params, n_honest: usize) {
    println!("\n{:=<78}", "");
    println!("{}  (omega = {}, k = {}, sig_len = {})", p.name, p.omega, p.k, p.sig_len);
    println!("{:=<78}", "");

    let mut rng = StdRng::from_seed([0xff; 32]);
    let mut counter = perf_event::Builder::new().build().expect("perf counter");

    // ---- part 1: honest hint weight distribution -------------------------
    let sigs = honest_sigs::<P>(&mut rng, n_honest);
    let weights: Vec<usize> = sigs.iter().map(|s| hint_weight(p, s)).collect();
    let wmin = *weights.iter().min().unwrap();
    let wmax = *weights.iter().max().unwrap();
    let wmean = weights.iter().sum::<usize>() as f64 / weights.len() as f64;
    let n_at_omega = weights.iter().filter(|&&w| w == p.omega).count();
    println!(
        "\n[1] honest hint weight over {} signatures: min {}, max {}, mean {:.1}, \
         reached omega={} in {} ({:.2}%)",
        n_honest, wmin, wmax, wmean, p.omega, n_at_omega,
        100.0 * n_at_omega as f64 / n_honest as f64
    );
    // coarse histogram
    let buckets = 10usize;
    let mut hist = vec![0usize; buckets];
    for &w in &weights {
        let b = (w * buckets / (p.omega + 1)).min(buckets - 1);
        hist[b] += 1;
    }
    for (b, c) in hist.iter().enumerate() {
        let lo = b * (p.omega + 1) / buckets;
        let hi = (b + 1) * (p.omega + 1) / buckets - 1;
        println!("    weight {:>3}-{:<3} | {:<5} {}", lo, hi, c, "#".repeat(c * 40 / n_honest));
    }

    // ---- part 2: crafted cost vs weight and layout -----------------------
    let base = &sigs[0];
    let concentrated = |w: usize| {
        let mut c = vec![0usize; p.k];
        c[p.k - 1] = w;
        c
    };
    let spread = |w: usize| {
        let mut c = vec![0usize; p.k];
        let mut acc = 0;
        for j in 0..p.k {
            acc += w / p.k + usize::from(j < w % p.k);
            c[j] = acc;
        }
        c
    };

    println!("\n[2] decode cost vs hint weight (min of {} runs, crafted hints)", REPEATS);
    println!("    {:>7}  {:>14}  {:>14}", "weight", "concentrated", "spread");
    let mut rows = Vec::new();
    for &w in &[0, p.omega / 4, p.omega / 2, 3 * p.omega / 4, p.omega] {
        let c_conc = measure_decode::<P>(&mut counter, &craft(p, base, &concentrated(w)));
        let c_spread = measure_decode::<P>(&mut counter, &craft(p, base, &spread(w)));
        println!("    {:>7}  {:>14}  {:>14}", w, c_conc, c_spread);
        rows.push((w, c_conc, c_spread));
    }
    let (best_w, best_cost, best_layout) = rows
        .iter()
        .flat_map(|&(w, a, b)| [(w, a, "concentrated"), (w, b, "spread")])
        .max_by_key(|&(_, c, _)| c)
        .unwrap();
    println!(
        "    -> most expensive: weight {} / {} layout at {} insns",
        best_w, best_layout, best_cost
    );

    // ---- part 3: honest vs ceiling --------------------------------------
    let honest_at_max = sigs
        .iter()
        .max_by_key(|s| hint_weight(p, s))
        .unwrap()
        .clone();
    let c_honest_max = measure_decode::<P>(&mut counter, &honest_at_max);
    let c_ceiling = measure_decode::<P>(&mut counter, &craft(p, base, &concentrated(p.omega)));
    let c_honest_min = {
        let s = sigs.iter().min_by_key(|s| hint_weight(p, s)).unwrap();
        measure_decode::<P>(&mut counter, s)
    };
    println!("\n[3] gap analysis");
    println!("    honest at min weight ({:>3}) : {:>8} insns", wmin, c_honest_min);
    println!("    honest at max weight ({:>3}) : {:>8} insns", wmax, c_honest_max);
    println!("    crafted ceiling      ({:>3}) : {:>8} insns", p.omega, c_ceiling);
    let gap = c_ceiling as i64 - c_honest_max as i64;
    println!(
        "    gap (ceiling - honest max)  : {:>8} insns ({:+.3}%)",
        gap,
        100.0 * gap as f64 / c_honest_max as f64
    );
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    println!("ML-DSA Signature::decode hint-weight experiment");
    println!("honest sample count per variant: {}", n);
    run::<MlDsa44>(&P44, n);
    run::<MlDsa65>(&P65, n);
    run::<MlDsa87>(&P87, n);
}
