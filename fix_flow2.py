with open('src/auth/srp/flow.rs') as f:
    lines = f.readlines()

# In dòng 60-100 hiện tại
print("=== Dòng 60-100 hiện tại ===")
for i in range(59, min(100, len(lines))):
    print(f"{i+1}: {lines[i].rstrip()}")
