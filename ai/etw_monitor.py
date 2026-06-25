"""
etw_monitor.py — Real-time ETW event stream for dashboard
Integrates with C++ ETWBridge.dll via ctypes
"""

import ctypes
import json
import asyncio
import threading
from pathlib import Path
from collections import deque
from datetime import datetime
import logging

log = logging.getLogger("etw_monitor")

class ETWMonitor:
    def __init__(self):
        self.dll = None
        self.handle = None
        self.events_buffer = deque(maxlen=500)  # Last 500 events
        self.is_running = False
        self._load_dll()
    
    def _load_dll(self):
        """Load ETWBridge.dll (after build)"""
        dll_path = Path(__file__).parent.parent / "scanner" / "build" / "Release" / "ETWBridge.dll"
        try:
            self.dll = ctypes.CDLL(str(dll_path))
            log.info(f"✓ ETW DLL loaded: {dll_path}")
        except Exception as e:
            log.warning(f"ETW DLL not found (Phase 2 not built yet): {e}")
            self.dll = None
    
    def start(self):
        """Start monitoring ETW events"""
        if not self.dll:
            log.warning("ETW not available - skipping")
            return False
        
        try:
            # Create consumer handle
            create_consumer = self.dll.ETW_CreateConsumer
            create_consumer.restype = ctypes.c_void_p
            self.handle = create_consumer()
            
            # Start listening
            start = self.dll.ETW_Start
            start.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            start.restype = ctypes.c_bool
            
            if start(self.handle, "HeuristicScanner"):
                self.is_running = True
                log.info("✓ ETW Monitor started")
                return True
        except Exception as e:
            log.error(f"Failed to start ETW: {e}")
        
        return False
    
    def stop(self):
        """Stop monitoring"""
        if not self.dll or not self.handle:
            return
        
        try:
            stop = self.dll.ETW_Stop
            stop.argtypes = [ctypes.c_void_p]
            stop(self.handle)
            
            destroy = self.dll.ETW_DestroyConsumer
            destroy.argtypes = [ctypes.c_void_p]
            destroy(self.handle)
            
            self.is_running = False
            log.info("✓ ETW Monitor stopped")
        except Exception as e:
            log.error(f"Failed to stop ETW: {e}")
    
    def poll_events(self) -> list:
        """Get buffered events (non-blocking)"""
        if not self.dll or not self.handle:
            return []
        
        events = []
        try:
            get_next = self.dll.ETW_GetNextEvent
            get_next.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
            get_next.restype = ctypes.c_bool
            
            event_id = ctypes.c_int()
            out_data = ctypes.create_string_buffer(1024)
            
            while get_next(self.handle, ctypes.byref(event_id), out_data):
                try:
                    data = json.loads(out_data.value.decode('utf-8'))
                    data['timestamp'] = datetime.now().isoformat()
                    data['event_id'] = event_id.value
                    
                    self.events_buffer.append(data)
                    events.append(data)
                except Exception as e:
                    log.error(f"Failed to parse event: {e}")
        
        except Exception as e:
            log.debug(f"Poll error (expected if no events): {e}")
        
        return events
    
    def get_recent_events(self, minutes=5) -> list:
        """Get events from last N minutes"""
        return list(self.events_buffer)  # Simple: just return all buffered


# Global instance
_monitor = ETWMonitor()

def init_etw():
    """Initialize ETW monitoring"""
    return _monitor.start()

def get_etw_events() -> list:
    """Get new events since last poll"""
    return _monitor.poll_events()

def get_etw_timeline() -> list:
    """Get event timeline for dashboard"""
    return _monitor.get_recent_events()