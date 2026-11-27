/-!
# Mapping 32-byte values into the BN254 scalar field

Groth16 public inputs must be canonical BN254 scalars (`< r`). Pubkeys and
SHA-256 digests are arbitrary 256-bit values and frequently exceed `r`
(probability ≈ 0.81 per value), so the current program's
`build_public_inputs` passes non-canonical inputs. The Rust core splits each
32-byte value into two 128-bit limbs; this file proves the split is
canonical and lossless.
-/
namespace ClawdZk

/-- BN254 scalar field modulus. -/
def bn254R : Nat :=
  21888242871839275222246405745257275088548364400416034343698204186575808495617

def split128 (x : Nat) : Nat × Nat := (x / 2 ^ 128, x % 2 ^ 128)

def join128 (p : Nat × Nat) : Nat := p.1 * 2 ^ 128 + p.2

theorem split128_canonical (x : Nat) (h : x < 2 ^ 256) :
    (split128 x).1 < bn254R ∧ (split128 x).2 < bn254R := by
  simp only [split128, bn254R]
  omega

theorem join_split128 (x : Nat) : join128 (split128 x) = x := by
  simp only [join128, split128]
  omega

theorem split128_injective {x y : Nat} (h : split128 x = split128 y) : x = y := by
  rw [← join_split128 x, ← join_split128 y, h]

/-- 2^256 - 1 is not a canonical scalar: raw 32-byte inputs are unsafe. -/
theorem raw_bytes_not_canonical : ¬ (2 ^ 256 - 1 < bn254R) := by
  decide

end ClawdZk
