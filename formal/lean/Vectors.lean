import ClawdZk
open ClawdZk

def hex2 (n : Nat) : String :=
  let d := "0123456789abcdef".toList
  String.ofList [d[n / 16]!, d[n % 16]!]

def toHex (bs : List Nat) : String := String.join (bs.map hex2)

def strBytes (s : String) : List Nat := s.toUTF8.toList.map (·.toNat)

/-- (secret, context, nonce). Must match `rust/tests/vectors.rs`. -/
def cases : List (List Nat × String × Nat) :=
  [ (List.replicate 32 7, "model-attest:v1:abc", 0),
    (List.range 16, "", 1),
    (List.replicate 40 255, "consume:v1", 18446744073709551615) ]

def main : IO Unit := do
  for (s, c, k) in cases do
    IO.println s!"{toHex s} {toHex (strBytes c)} {k} {toHex (preimage s (strBytes c) k)}"
