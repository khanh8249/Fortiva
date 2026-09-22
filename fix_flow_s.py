with open('src/auth/srp/flow.rs') as f:
    c = f.read()

# Fix salt parse
old_salt = '''        let salt_b64 = init_resp
            .get("s")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 's'"))?;

        let salt = general_purpose::STANDARD
            .decode(salt_b64)
            .context("Decode salt base64 thất bại")?;'''

new_salt = '''        // Salt có thể là string (base64) hoặc data (raw)
        let salt = match init_resp.get("s") {
            Some(Value::String(s)) => general_purpose::STANDARD
                .decode(s)
                .context("Decode salt base64 thất bại")?,
            Some(Value::Data(d)) => d.to_vec(),
            other => {
                return Err(anyhow!(
                    "Response thiếu 's' hoặc sai type. Got: {:?}", other
                ));
            }
        };'''

if old_salt in c:
    c = c.replace(old_salt, new_salt)
    print("Fixed salt parse")
else:
    print("Salt pattern NOT FOUND - in ra đoạn hiện tại")

# Fix B parse
old_b = '''        let b_b64 = init_resp
            .get("B")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'B'"))?;

        let b_pub = general_purpose::STANDARD
            .decode(b_b64)
            .context("Decode B base64 thất bại")?;'''

new_b = '''        // B có thể là string (base64) hoặc data (raw)
        let b_pub = match init_resp.get("B") {
            Some(Value::String(s)) => general_purpose::STANDARD
                .decode(s)
                .context("Decode B base64 thất bại")?,
            Some(Value::Data(d)) => d.to_vec(),
            other => {
                return Err(anyhow!(
                    "Response thiếu 'B' hoặc sai type. Got: {:?}", other
                ));
            }
        };'''

if old_b in c:
    c = c.replace(old_b, new_b)
    print("Fixed B parse")
else:
    print("B pattern NOT FOUND")

# Fix c parse  
old_c = '''        let c = init_resp
            .get("c")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'c'"))?
            .to_string();'''

new_c = '''        let c = init_resp
            .get("c")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'c'"))?
            .to_string();'''

# c giữ nguyên vì Python cũng dùng str

with open('src/auth/srp/flow.rs', 'w') as f:
    f.write(c)

print("Done")
