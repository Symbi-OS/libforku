import os
import time
print(os.getpid())

i = 0
while i < 20:
    i += 1
    time.sleep(1)
    print(f'i is {i}')

