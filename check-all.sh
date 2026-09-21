#!/data/data/com.termux/files/usr/bin/bash
# check-all.sh - Kiểm tra lỗi syntax + paste trong project Rust

echo "═══════════════════════════════════════════════"
echo "  FORTIVA SYNTAX CHECKER"
echo "═══════════════════════════════════════════════"
echo ""

errors=0

# ============================================================
# 1. Kiểm tra cân bằng dấu ngoặc
# ============================================================
echo "[1/6] Kiểm tra cân bằng ngoặc..."
for f in $(find src -name "*.rs"); do
    for pair in "{}" "()" "[]"; do
        open_char="${pair:0:1}"
        close_char="${pair:1:1}"
        
        o=$(grep -oF "$open_char" "$f" 2>/dev/null | wc -l)
        c=$(grep -oF "$close_char" "$f" 2>/dev/null | wc -l)
        
        if [ "$o" != "$c" ]; then
            echo "  ❌ $f: $open_char$close_char lệch ($o / $c)"
            errors=$((errors + 1))
        fi
    done
done
[ $errors -eq 0 ] && echo "  ✅ Tất cả cân bằng"

# ============================================================
# 2. Kiểm tra dấu ngoặc kép
# ============================================================
echo ""
echo "[2/6] Kiểm tra dấu ngoặc kép..."
quote_errors=0 Ki
for f in $(find src -name "*.rs"); do
    # Đếm dấu " không nằm trong comment
    q=$(grep -v '^\s*//ểm' "$f" | grep -o '"' | wc -l)
    if [ $ tra((q % 2)) -ne 0 ]; then
        echo "  ❌ $f: $q d functionấu \" (lẻ)"
        quote_errors=$((quote_errors + 1))
    fi
done
[ $quote_errors -eq 0 ] && echo "  ✅ Tất cả chẵn"

# ============================================================
# 3. Kiểm tra lỗi paste phổ biến
# ============================================================
echo ""
echo "[3/6] Kiểm tra lỗi paste..."
paste_errors=0

# 3.1: anyhow không có ! hoặc format string
if grep -rn "anyhow [a-z]" src/ 2>/dev/null | grep -v "anyhow!" | grep -v "\.rs://"; then
    echo "  ❌ anyhow thiếu ! hoặc format"
    paste_errors=$((paste_errors + 1))
fi

# 3.2: col srlections (collections bị tách)
if grep -rn "col srlections\|collections s" src/ 2>/dev/null | grep -v "\.rs://"; then
    echo "  ❌ 'collections' bị tách"
    paste_errors=$((paste_errors + 1))
fi

# 3.3: :: &self
if grep -rn ":: &self\|::&self" src/ 2>/dev/null; then
    echo "  ❌ ':: &self' thừa ::"
    paste_errors=$((paste_errors + 1))
fi

# 3.4: .and_then(else, .map(else
if grep -rn "\.and_then(else\|\.map(else\|\.ok_or(else" src/ 2>/dev/null; then
    echo "  ❌ closure bị mất |"
    paste_errors=$((paste_errors + 1))
fi

# 3.5: ||: hoặc : bị tách
if grep -rn "||:" src/ 2>/dev/null; then
    echo "  ❌ '||:' lỗi paste"
    paste_errors=$((paste_errors + 1))
fi

# 3.6: :: bị tách ở đầu dòng
if grep -rn "^\s*::" src/ 2>/dev/null | grep -v "^\s*//"; then
    echo "  ❌ '::' đầu dòng"
    paste_errors=$((paste_errors + 1))
fi

# 3.7: use std::col (không có ections)
if grep -rn "use std::col[^l]" src/ 2>/dev/null; then
    echo "  ❌ 'use std::col...' lỗi"
    paste_errors=$((paste_errors + 1))
fi

# 3.8: pub mod X use (thiếu ;)
if grep -rn "pub mod .* use;" src/ 2>/dev/null; then
    echo "  ❌ 'pub mod X use;' lỗi"
    paste_errors=$((paste_errors + 1))
fi

[ $paste_errors -eq 0 ] && echo "  ✅ Không phát hiện lỗi paste"

# ============================================================
# 4. signature lỗi
# ============================================================
echo ""
echo "[4/6] Kiểm tra function signature..."
sig_errors=0

# fn thiếu (
if grep -rnE "^\s*(pub )?fn [a-z_]+[^(;{]" src/ 2>/dev/null | grep -v "\.rs://"; then
    echo "  ❌ fn thiếu ("
    sig_errors=$((sig_errors + 1))
fi

# pub fn new thiếu pub
if grep -rn "^\s*sid: String" src/ 2>/dev/null; then
    echo "  ❌ 'pub fn new' bị mất"
    sig_errors=$((sig_errors + 1))
fi

[ $sig_errors -eq 0 ] && echo "  ✅ Signature OK"

# ============================================================
# 5. Kiểm tra các file bắt buộc
# ============================================================
echo ""
echo "[5/6] Kiểm tra cấu trúc file..."

required_files=(
    "src/main.rs"
    "src/lib.rs"
    "src/constants.rs"
    "src/auth/mod.rs"
    "src/auth/anisette.rs"
    "src/auth/gsa.rs"
    "src/auth/crypto/mod.rs"
    "src/auth/crypto/aes.rs"
    "src/auth/crypto/hmac.rs"
    "src/auth/crypto/cookie.rs"
    "src/auth/srp/mod.rs"
    "src/auth/srp/variant.rs"
    "src/auth/srp/flow.rs"
    "src/auth/twofa/mod.rs"
    "src/auth/twofa/trusted.rs"
    "src/auth/twofa/sms.rs"
    "src/dev/mod.rs"
    "src/dev/client.rs"
    "src/dev/plist_api.rs"
    "src/dev/json_api.rs"
    "src/dev/certificate.rs"
    "src/dev/teams.rs"
    "src/dev/devices.rs"
    "src/dev/app_ids.rs"
    "src/sideload/mod.rs"
    "src/sideload/bundle.rs"
    "src/sideload/application.rs"
    "src/sideload/cert_identity.rs"
    "src/sideload/entitlements.rs"
    "src/sideload/signer.rs"
    "src/sideload/sideloader.rs"
    "src/install/mod.rs"
    "src/install/device.rs"
    "src/install/afc.rs"
    "src/install/afc_rsd.rs"
    "src/install/installer.rs"
    "src/tools/mod.rs"
    "src/tools/sidestore_pairing.rs"
    "Cargo.toml"
)

missing=0
for f in "${required_files[@]}"; do
    if [ ! -f "$f" ]; then
        echo "  ❌ Thiếu: $f"
        missing=$((missing + 1))
    fi
done
[ $missing -eq 0 ] && echo "  ✅ Đủ ${#required_files[@]} file"

# ============================================================
# 6. Kiểm tra Cargo.toml
# ============================================================
echo ""
echo "[6/6] Kiểm tra Cargo.toml..."

if [ -f "Cargo.toml" ]; then
    # Check plist version
    if grep -q '^plist = "0.7"' Cargo.toml; then
        echo "  ⚠️  plist = \"0.7\" không tồn tại, nên dùng \"1.7\""
    fi

    # Check idevice
    if grep -q 'idevice.*= "0.1"' Cargo.toml; then
        echo "  ⚠️  idevice = \"0.1\" nên pin \"=0.1.68\""
    fi

    if grep -q 'idevice.*features.*"lockdown"' Cargo.toml; then
        echo "  ⚠️  idevice feature 'lockdown' không tồn tại"
    fi

    echo "  ✅ Cargo.toml tồn tại"
fi

# ============================================================
# Tổng kết
# ============================================================
echo ""
echo "═══════════════════════════════════════════════"
total_errors=$((errors + quote_errors + paste_errors + sig_errors + missing))
if [ $total_errors -eq 0 ]; then
    echo "  ✅ PASS - Không có lỗi syntax"
    echo ""
    echo "  Có thể push lên GitHub:"
    echo "    git add -A"
    echo "    git commit -m 'fix: syntax'"
    echo "    git push"
else
    echo "  ❌ FAIL - $total_errors lỗi cần fix"
    echo ""
    echo "  Xem log ở trên để fix từng file"
fi
echo "═══════════════════════════════════════════════"
