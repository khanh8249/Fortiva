#!/data/data/com.termux/files/usr/bin/bash
echo "═══════════════════════════════════"
echo "  FORTIVA SCAN"
echo "═══════════════════════════════════"
E=0

echo ""
echo "[1] Can bang {} () []"
for f in $(find src -name "*.rs"); do
  for p in "{}" "()" "[]"; do
    O=$(grep -oF "${p%?}" "$f" | wc -l)
    C=$(grep -oF "${p#?}" "$f" | wc -l)
    [ "$O" != "$C" ] && echo "  X $f: $p ($O/$C)" && E=1
  done
done

echo ""
echo "[2] Ngoac kep le"
for f in $(find src -name "*.rs"); do
  Q=$(grep -o '"' "$f" | wc -l)
  [ $((Q % 2)) -ne 0 ] && echo "  X $f: $Q" && E=1
done

echo ""
echo "[3] Pattern loi paste"
grep -rln "col srlections" src/ 2>/dev/null && E=1
grep -rln ":: &self" src/ 2>/dev/null && E=1
grep -rln "||:" src/ 2>/dev/null && E=1
grep -rln "pub mod .* use;" src/ 2>/dev/null && E=1
grep -rn "anyhow [a-z]" src/ 2>/dev/null | grep -v "anyhow!" && E=1
grep -rln "\.and_then(else" src/ 2>/dev/null && E=1
grep -rln "\.map(else" src/ 2>/dev/null && E=1
grep -rln "(d  " src/ 2>/dev/null && E=1
grep -rln "^\s*let());" src/ 2>/dev/null && E=1

echo ""
echo "[4] Khoang trang bat thuong (>20 space giua text)"
for f in $(find src -name "*.rs"); do
  N=$(grep -cE "[a-zA-Z]{2} {10,}[a-zA-Z]{2}" "$f" 2>/dev/null)
  [ "$N" -gt 0 ] && echo "  ? $f: $N dong" && E=1
done

echo ""
echo "[5] File thieu"
for f in src/main.rs src/lib.rs Cargo.toml; do
  [ ! -f "$f" ] && echo "  X thieu $f" && E=1
done

echo ""
if [ $E -eq 0 ]; then
  echo "PASS"
else
  echo "FAIL - xem dong X o tren"
fi
echo "═══════════════════════════════════"
