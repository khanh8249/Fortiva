#!/bin/sh
echo "Check syntax Fortiva..."
E=0

echo ""
echo "[1] Can bang ngoac"
for f in $(find src -name "*.rs"); do
    for p in "{}" "()" "[]"; do
        o=$(grep -oF "${p%?}" "$f" | wc -l)
        c=$(grep -oF "${p#?}" "$f" | wc -l)
        if [ "$o" != "$c" ]; then
            echo "  LOI $f: ${p} lech ($o/$c)"
            E=1
        fi
    done
done
[ $E -eq 0 ] && echo "  OK"

echo ""
echo "[2] Dau ngoac kep le"
for f in $(find src -name "*.rs"); do
    q=$(grep -o '"' "$f" | wc -l)
    if [ $((q % 2)) -ne 0 ]; then
        echo "  LOI $f: $q dau \" (le)"
        E=1
    fi
done

echo ""
echo "[3] Loi paste"
grep -rn "col srlections" src/ && E=1
grep -rn ":: &self" src/ && E=1
grep -rn "||:" src/ && E=1
grep -rn "anyhow [a-z]" src/ | grep -v "anyhow!" && E=1
grep -rn "pub mod .* use;" src/ && E=1

echo ""
if [ $E -eq 0 ]; then
    echo "PASS - Khong co loi"
else
    echo "FAIL - Co loi can fix"
fi
