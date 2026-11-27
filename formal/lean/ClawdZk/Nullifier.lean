import ClawdZk.Bytes
/-!
# Nullifier preimage encoding

The Rust core hashes `preimage s c k` with SHA-256. SHA-256 itself is an
assumption (collision resistance), not something proved here. What *is*
proved: the preimage encoding is injective, so distinct
`(secret, context, nonce)` triples never feed the hash the same bytes.
Any nullifier collision is therefore a SHA-256 collision.

The legacy TypeScript construction `sha256(secret ‖ context ‖ nonce)`
(`client/src/nullifier.ts`) has no such property; `legacy_not_injective`
is a concrete counterexample.
-/
namespace ClawdZk

/-- ASCII "clawd-zk-nullifier/v1". -/
def domainTag : List Nat :=
  [99,108,97,119,100,45,122,107,45,110,117,108,108,105,102,105,101,114,47,118,49]

def lenPrefixed (xs : List Nat) : List Nat := encodeLE 4 xs.length ++ xs

def preimage (secret context : List Nat) (nonce : Nat) : List Nat :=
  domainTag ++ lenPrefixed secret ++ lenPrefixed context ++ encodeLE 8 nonce

/-- Reads one length-prefixed field; returns the field and the rest. -/
def readField (bs : List Nat) : List Nat × List Nat :=
  let n := decodeLE (bs.take 4)
  ((bs.drop 4).take n, (bs.drop 4).drop n)

theorem readField_lenPrefixed (xs rest : List Nat) (h : xs.length < 2 ^ 32) :
    readField (lenPrefixed xs ++ rest) = (xs, rest) := by
  have h' : xs.length < 256 ^ 4 := by simpa using h
  simp [readField, lenPrefixed,
    decodeLE_encodeLE 4 _ h']

def decode (bs : List Nat) : List Nat × List Nat × Nat :=
  let body := bs.drop domainTag.length
  let (s, r1) := readField body
  let (c, r2) := readField r1
  (s, c, decodeLE r2)

theorem decode_preimage (s c : List Nat) (k : Nat)
    (hs : s.length < 2 ^ 32) (hc : c.length < 2 ^ 32) (hk : k < 2 ^ 64) :
    decode (preimage s c k) = (s, c, k) := by
  have hk' : k < 256 ^ 8 := by simpa using hk
  simp only [decode, preimage, List.append_assoc, List.drop_left]
  rw [readField_lenPrefixed _ _ hs, readField_lenPrefixed _ _ hc,
    decodeLE_encodeLE 8 _ hk']

/-- Main theorem: the v1 preimage encoding is injective on its domain. -/
theorem preimage_injective {s c s' c' : List Nat} {k k' : Nat}
    (hs : s.length < 2 ^ 32) (hc : c.length < 2 ^ 32) (hk : k < 2 ^ 64)
    (hs' : s'.length < 2 ^ 32) (hc' : c'.length < 2 ^ 32) (hk' : k' < 2 ^ 64)
    (h : preimage s c k = preimage s' c' k') :
    s = s' ∧ c = c' ∧ k = k' := by
  have e := congrArg decode h
  rw [decode_preimage _ _ _ hs hc hk, decode_preimage _ _ _ hs' hc' hk'] at e
  simp only [Prod.mk.injEq] at e
  exact e

/-- The legacy construction: plain concatenation, no lengths, no tag. -/
def legacyPreimage (secret context nonce : List Nat) : List Nat :=
  secret ++ context ++ nonce

/-- Counterexample: shifting a byte between secret and context collides. -/
theorem legacy_not_injective :
    legacyPreimage [1, 2] [3] [] = legacyPreimage [1] [2, 3] [] ∧
      ([1, 2] : List Nat) ≠ [1] := by
  decide

end ClawdZk
