from pwn import*
import os
dir_path = "./"
contents = os.listdir(dir_path)
# if os.path.isdir(di)
pwn_path = []
for item in contents:
    if os.path.isdir(os.path.join(dir_path,item)):
        print(item)
print(contents)