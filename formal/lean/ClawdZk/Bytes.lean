/-!
# Little-endian fixed-width integer encoding

Bytes are modelled as `Nat`s; `encodeLE w n` is the `w`-byte little-endian
encoding used by the Rust core (`u32::to_le_bytes`, `u64::to_le_bytes`).
-/
namespace ClawdZk

def encodeLE : Nat → Nat → List Nat
  | 0, _ => []
  | w + 1, n => n % 256 :: encodeLE w (n / 256)

def decodeLE : List Nat → Nat
  | [] => 0
  | b :: bs => b + 256 * decodeLE bs

@[simp] theorem length_encodeLE (w n : Nat) : (encodeLE w n).length = w := by
  induction w generalizing n with
  | zero => rfl
  | succ w ih => simp [encodeLE, ih]

theorem encodeLE_bytes (w n : Nat) : ∀ b ∈ encodeLE w n, b < 256 := by
  induction w generalizing n with
  | zero => simp [encodeLE]
  | succ w ih =>
    intro b hb
    simp only [encodeLE, List.mem_cons] at hb
    rcases hb with rfl | hb
    · exact Nat.mod_lt _ (by decide)
    · exact ih _ b hb

/-- Decoding inverts encoding for every value that fits in `w` bytes. -/
theorem decodeLE_encodeLE (w n : Nat) (h : n < 256 ^ w) :
    decodeLE (encodeLE w n) = n := by
  induction w generalizing n with
  | zero => simp [encodeLE, decodeLE] at *; omega
  | succ w ih =>
    have hq : n / 256 < 256 ^ w := by
      rw [Nat.pow_succ] at h
      exact (Nat.div_lt_iff_lt_mul (by decide)).2 h
    simp only [encodeLE, decodeLE, ih _ hq]
    omega

theorem encodeLE_injective (w a b : Nat) (ha : a < 256 ^ w) (hb : b < 256 ^ w)
    (h : encodeLE w a = encodeLE w b) : a = b := by
  rw [← decodeLE_encodeLE w a ha, ← decodeLE_encodeLE w b hb, h]

end ClawdZk
