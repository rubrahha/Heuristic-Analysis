import win32pipe
import win32file
import pywintypes
import time

PIPE_NAME = r'\\.\pipe\HeuristicSensorPipe'

def start_listening():
    print(f"[*] Python Engine starting Named Pipe Server: {PIPE_NAME}")
    
    while True:
        try:
            # Create the Named Pipe
            pipe = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_INBOUND,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None
            )
            
            # Wait for the C++ Sensor to connect
            win32pipe.ConnectNamedPipe(pipe, None)
            
            # Read the JSON payload (Wide strings = 2 bytes per char, so we read a big chunk)
            hr, data = win32file.ReadFile(pipe, 65536)
            
            # Decode the wide string sent from C++
            payload = data.decode('utf-16le')
            print(f"\n[+] PYTHON RECEIVED: {payload}")
            
            # Clean up the pipe for the next event
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
            
        except pywintypes.error as e:
            if e.winerror == 232: # Pipe closed normally
                win32file.CloseHandle(pipe)
            else:
                print(f"[-] Pipe Error: {e}")
                time.sleep(1)

if __name__ == "__main__":
    start_listening()