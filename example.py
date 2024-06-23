from symcrypt.main import secureFile
import os

cwd = os.getcwd()
file_path = os.path.join(cwd , "abc.txt")

file_main  = secureFile(file_path , "abc"   , "w")
file_main.write("hello mate")

file_two = secureFile(file_path , "abc"   , "rb")
a = file_two.read()
print(a)