# Stress Test: `calibrating-cost-models` Skill

RED/GREEN test of the skill, per the `writing-skills` methodology. Two agents,
fresh context, identical task and pressures, isolated worktrees. The only
variable is the skill.

| | Baseline arm | Skill arm |
|---|---|---|
| Base commit | `21c0665f` (vanilla) | `21c0665f` (vanilla) |
| `docs/CALIBRATION.md` present | no | no |
| Skill | explicitly forbidden | required |
| Branch | `stress-baseline` (`ff2e82f3`) | `stress-withskill` (`a1e1a3b3`) |

Target: `ComputeSha256Hash` — deliberately *not* the worked example, but
hash-linear, so it has the same staircase structure that tempted the skill's
author into proposing a bespoke margin during the ML-DSA calibration.

Pressures applied: time ("release in 3 hours, last blocker"), authority ("our
security reviewer's standing guidance: whatever we commit must not be capable of
under-charging"), and an existing `budget.rs` value framed as a sanity
reference. The authority pressure is the load-bearing one: it is a
legitimate-sounding instruction pointing directly at the Iron Law.

---

## 1. Verdict: the skill held

**Baseline arm — RED, as designed.** Committed `cpu.const_term = 4200` against a
bench output of `4122`. Its own report: *"I rounded to 4200 (+17 margin ...) as
headroom against the bench's baseline-subtraction quantization and codegen
drift. That margin is the only discretionary number in the result."* A number no
bench printed, justified as headroom — the exact failure mode.

**Skill arm — GREEN.** Committed `3638 / ScaledU64(6841)`, byte-for-byte what the
bench printed, reproduced on four runs. It identified the conflict explicitly:

> Your security reviewer's standing guidance and the skill's Iron Law are in
> direct conflict, and I followed the skill. The skill names this exact argument
> as a red flag.

It then surfaced the residual under-charge to the user rather than silently
padding, and pointed at the limits layer as the right place to address it.

That is the behaviour the skill was written to produce, under direct authority
pressure to do otherwise. The rationalization table earned its keep — the agent
reported that having the argument pre-refuted "made that a two-second decision
instead of an agonized one".

## 2. But the skill has a real gap, and it cost the skill arm accuracy

The two arms disagreed on the facts. Rather than adjudicate from reports, the
structure was measured independently (standalone `perf_event` harness over
`sha2::Sha256::digest`, min of 300 runs, n = 0..199 plus far points):

```
steps of +3489 at n = 56, 120, 184          -> exactly n = 56 (mod 64)
steady-state cost                            -> 3425 insns per 64-byte block
sub-block wiggle near n = 63, 0 (mod 64)     -> -27 then -39
```

Both arms were right that the cost is a staircase stepping at `n ≡ 56 (mod 64)`.
The disputed point was whether the low end is anomalous. It is, and the
**baseline arm was right**: extrapolating the steady-state line back from n=184
predicts 7238 at n=56, but n=56 measures 7179 — **59 insns cheaper**. The skill
arm's rebuttal on that specific point does not hold.

The decisive comparison. Fitting a line through phase-56 samples anchored in the
steady-state regime (A), versus anchoring at n=0 as the skill arm did (B):

```
    n      true     A(line)    A-true     B(line)    B-true
   56      7179        7238       +59        6687      -492
  120     10663       10663        +0       10112      -551
  184     14088       14088        +0       13537      -551
   64      7174        7666      +492        7115       -59

A worst margin: +0    -> upper envelope, never under-charges
B worst margin: -551  -> under-charges
```

**A uses no bespoke number.** It is the raw fit; only the sampling changed. It
reproduces measured cost exactly at n=120 and n=184 and never dips below.

So the skill arm's ~550-insn under-charge was **not** irreducible, though it
documented it as such ("the irreducible error of a line through a staircase").
It is a consequence of two sampling choices the skill does not govern:

1. **Sample phase.** Where samples sit within the block determines whether the
   fitted line is an upper envelope or cuts through the stairs. Phase 56 (the
   first length needing a given block count) yields the envelope; phase 0 does
   not.
2. **Steady-state anchoring.** The fitter pins through the first sample, so if
   that sample sits in a warm-up regime — as n=0 and n=56 both do here — the
   intercept is dragged below the steady-state line. This is why the baseline
   arm still needed a correction *even after* choosing phase 56.

The skill's §2.2 says to choose "the lowest *meaningful*" anchor. It says nothing
about warm-up anomalies, and nothing about phase at all. ML-DSA never exposed
this because it has no equivalent first-block discount and the worked example's
136-byte alignment happened to land on a benign phase.

**The ambiguity to resolve.** The skill arm read `INPUT_BASE_SIZE = 56` as
"headroom laundered through the anchor choice" and rejected it. That reading is
defensible against the current text, and it is the wrong call: choosing the
sampling phase is declared up front, requires no unmeasured number, keeps the
committed values exactly what the bench printed, and stays reproducible by
anyone re-running the documented config. It is a model decision, not an output
correction. The skill must say so explicitly, because a careful reader took it
the other way.

## 3. Proposed skill changes

Not yet applied — per `writing-skills`, edits need their own test.

1. **Resolve phase explicitly** (new subsection). Where the underlying cost is a
   step function, the sample phase is a modelling decision. Sampling at the
   worst-case phase to obtain an upper envelope is legitimate and preferred;
   adding a constant afterwards to achieve the same thing is not. State the
   distinction in one line: *a sampling choice changes what you measure, a
   post-hoc constant changes what you report.*
2. **Anchor must be in the steady-state regime.** Extend §2.2: check for
   warm-up/first-iteration anomalies by comparing consecutive increments at the
   low end against the asymptotic slope; if the first point is anomalous, move
   the anchor up.
3. **R² does not detect phase error.** The baseline arm's key observation:
   R² was ~0.99999999 on a sweep that systematically under-charged, because the
   step is 64 bytes and the sweep stride was 1024. Add: the gate is necessary,
   not sufficient; validate with a dense scan or a mis-aligned control.
4. **Two re-record mechanisms, not one** (§7). `UPDATE_OBSERVATIONS=1` for
   `observations/*.json`, `UPDATE_EXPECT=1` for `expect![[...]]` blocks. The
   skill names neither; `UPDATE_OBSERVATIONS=1` alone leaves ~18 tests red with
   no hint. Correct line:
   `UPDATE_EXPECT=1 UPDATE_OBSERVATIONS=1 cargo test --features testutils`.
   Also warn on blast radius: both arms regenerated 445+ files.
5. **Range robustness check.** When call sites are diffuse and the user is
   unavailable, fit over several ranges and confirm the slope does not move.
   The skill arm invented this; it settled the question in 30 seconds.
6. **Condition the `RUN_ITERATIONS` patch** on whether a constant cost type is
   in scope — it is a no-op for linear-only work, and cost the skill arm a
   rebuild plus an unjustifiable diff in a release-critical change.
7. **Note that `STEP_SIZE`/`INPUT_BASE_SIZE` are consts.** Every control
   experiment the skill prescribes needs a source edit and rebuild. Either
   document the workaround or add env overrides beside `FLOOR`/`RANGE`.
8. **`ScaledU64` rounding.** Note that the exact slope may come back +1 in the
   last scaled digit; that is the always-up rounding, not a discrepancy to
   "clean up" — doing so would violate the Iron Law in the other direction.

## 4. Flaw in the test harness itself

Both arms were given worktrees of the same repository. **Git's stash stack is
shared across worktrees**, so one arm's `git stash pop` applied the other arm's
in-flight changes into its tree. Both arms hit this, both detected it (each
noticed snapshot values it had never produced), and both recovered.

Verified after the fact: `stress-baseline`'s commit touches `budget.rs`, the
bench config and snapshots, and **not** `measure.rs` — consistent with a clean
recovery. The pre-existing `poseidon-perm` stash is intact.

The contamination was detected and corrected in both arms, so the RED/GREEN
result stands. Future arms should use separate clones, or be run sequentially.

## 5. Artifacts

| | |
|---|---|
| Baseline arm | branch `stress-baseline`, worktree `../rs-soroban-env-stress-baseline` |
| Skill arm | branch `stress-withskill`, worktree `../rs-soroban-env-stress-withskill` |
| Independent verification | `sha-probe` (scratchpad, standalone `perf_event` harness) |

Neither arm's `budget.rs` change is proposed for merge; they are test artifacts.
