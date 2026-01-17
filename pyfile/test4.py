# 三行输入，前两行随机，最后一行是-1
str1 = "myxRUC"
str2 = "Yes"
str3 = "-1"

# 拼接
payload = f"{str1}\n{str2}\n{str3}"

# 写入文件
with open("ans4.txt", "w", encoding="utf-8") as f:
    f.write(payload)
    
print("成功生成ans4.txt")