import re

with open('src/auth/srp/flow.rs') as f:
    content = f.read()

# In đoạn cần sửa để verify
print("=== TRƯỚC KHI SỬA ===")
match = re.search(r'let salt_b64 = init_resp.*?\.context\("Decode B that bai"\)\?;', content, re.DOTALL)
if match:
    print(match.group(0))
    print()

# Pattern cũ cần thay - dùng regex linh hoạt
old_pattern = r'''        let salt_b64 = init_resp
            \.get\("s"\)
            \.and_then\(\|v\| v\.as_string\(\)\)
            \.ok_or_else\(\|\| anyhow!\("Response thiếu 's'"\)\)\?;

        let b_b64 = init_resp
            \.get\("B"\)
            \.and_then\(\|v\| v\.as_string\(\)\)
            \.ok_or_else\(\|\| anyhow!\("Response thiếu 'B'"\)\)\?;'''

new_block = '''        // Salt: có thể String (base64) hoặc Data (raw bytes)
        let salt = match init_resp.get("s") {
            Some(Value::String(s)) => general_purpose::STANDARD
                .decode(s)
                .context("Decode salt base64 thất bại")?,
            Some(Value::Data(d)) => d.to_vec(),
            other => {
                return Err(anyhow!("Field 's' sai type: {:?}", other));
            }
        };

        // B: có thể String (base64) hoặc Data (raw bytes)
        let b_pub = match init_resp.get("B") {
            Some(Value::String(s)) => general_purpose::STANDARD
                .decode(s)
                .context("Decode B base64 thất bại")?,
            Some(Value::Data(d)) => d.to_vec(),
            other => {
                return Err(anyhow!("Field 'B' sai type: {:?}", other));
            }
        };'''

# Thay block cũ
if re.search(old_pattern, content):
    content = re.sub(old_pattern, new_block, content, count=1)
    print("✅ Đã thay block salt + B parse")
else:
    print("❌ Pattern không khớp — cần xem code thủ công")

# Bây giờ xoá đoạn decode cũ (đã dư thừa)
old_decode = r'''        let salt = general_purpose::STANDARD
            \.decode\(salt_b64\)
            \.context\("Decode salt that bai"\)\?;

        let b_pub = general_purpose::STANDARD
            \.decode\(b_b64\)
            \.context\("Decode B that bai"\)\?;'''

if re.search(old_decode, content):
    content = re.sub(old_decode, '', content, count=1)
    print("✅ Đã xoá đoạn decode cũ")
else:
    print("⚠️ Không tìm thấy đoạn decode cũ")

# Đảm bảo import Value
if 'use plist::{Dictionary, Value};' not in content:
    content = content.replace(
        'use plist::Dictionary;',
        'use plist::{Dictionary, Value};'
    )
    print("✅ Đã thêm Value import")

with open('src/auth/srp/flow.rs', 'w') as f:
    f.write(content)

# In kết quả
print()
print("=== SAU KHI SỬA ===")
with open('src/auth/srp/flow.rs') as f:
    content = f.read()

# In dòng 60-110
lines = content.split('\n')
for i in range(59, min(110, len(lines))):
    print(f"{i+1}: {lines[i]}")

# Verify balance
print()
print(f"Curly: {content.count('{')}/{content.count('}')}")
print(f"Paren: {content.count('(')}/{content.count(')')}")
