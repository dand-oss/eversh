import sys

while True:
    char = sys.stdin.read(1)
    if not char:
        break
    sys.stdout.write(char)
    sys.stdout.flush()
