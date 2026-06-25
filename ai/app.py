"""
app.py — HeuristicScanner AI web server (FastAPI Edition)
Runs via Uvicorn at http://localhost:5000

Enterprise Upgrades:
- Pydantic strict data validation
- Asynchronous Locks & Events
- Background Tasks for zero-blocking disk I/O
- StreamingResponse for native Server-Sent Events (SSE)
"""

import os
import json
import time
import uuid
import logging
import tempfile
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import deque
import win32pipe
import win32file
import pywintypes
import threading
import shlex
import multiprocessing
import sys

from fastapi import FastAPI, Request, File, UploadFile, BackgroundTasks, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator
import aiofiles
from fastapi.concurrency import run_in_threadpool

from bridge import scan_file, scan_folder



# ── Production Logging ──────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("webserver")

app = FastAPI(title="HeuristicScanner AI", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows your Tauri app to connect
    allow_credentials=True,
    allow_methods=["*"],  # Allows POST, GET, etc.
    allow_headers=["*"],
)



# ── PyInstaller Path Fix ──
if getattr(sys, 'frozen', False):
    _HERE = Path(sys._MEIPASS)
else:
    _HERE = Path(__file__).parent
LOG_FILE = _HERE / "logs" / "scan_history.json"
LOG_FILE.parent.mkdir(exist_ok=True)

# ── Templates ─────────────────────────────────────────────────────────────
templates = Jinja2Templates(directory=str(_HERE / "templates"))

# ── Data Validation Models ────────────────────────────────────────────────
# Upgrade 1: Pydantic replaces manual dictionary .get() hacking
class ScanPayload(BaseModel):
    path: str

    @field_validator('path')
    def clean_path(cls, v):
        cleaned = v.strip().replace('"', '').replace("'", '')
        if not cleaned:
            raise ValueError("Path cannot be empty")
        return cleaned

# ── Async Scan State Management ───────────────────────────────────────────
# Upgrade 2: Asyncio primitives replace heavy threading locks
_folder_lock   = asyncio.Lock()
_folder_active = False
_cancel_event  = asyncio.Event()

def _is_folder_scanning(): return _folder_active

async def _start_folder():
    global _folder_active
    _folder_active = True
    _cancel_event.clear()

async def _end_folder():
    global _folder_active
    _folder_active = False

# ── Async History Cache ───────────────────────────────────────────────────
_history_lock = asyncio.Lock()
_history_cache = []

def _init_history():
    global _history_cache
    if LOG_FILE.exists():
        try:
            _history_cache = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            log.error(f"Failed to load history: {e}")
            _history_cache = []

_init_history()

# Upgrade 3: Async File I/O to prevent blocking the event loop
async def _save_history_to_disk():
    try:
        async with aiofiles.open(LOG_FILE, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(_history_cache, indent=2))
    except Exception as e:
        log.error(f"Failed to write history to disk: {e}")
# Create a fast, thread-safe memory cache for the Live Dashboard (keeps last 200 events)
_timeline_cache = deque(maxlen=200)

import concurrent.futures

_etw_cache = {}
_etw_cache_lock = threading.Lock()

# ── OPTIMIZATION 2: The ETW Restrictor Pool ──
# This guarantees background monitoring never uses more than 2 CPU threads.
_etw_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="ETW_Worker")

def _kernel_listener_loop():
    PIPE_NAME = r'\\.\pipe\HeuristicSensorPipe'
    print(f"[*] Live Kernel Sensor Listener started on {PIPE_NAME}")
    
    THREAT_EXTS = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"}
    
    def _scan_and_cache(path):
        # ── OPTIMIZATION 3: The Ghost File Check ──
        # Let volatile temp files delete themselves before we waste CPU scanning them
        time.sleep(0.2) 
        if not os.path.exists(path):
            return 
            
        try:
            result = scan_file(path)
            history_item = {
                "id":          str(uuid.uuid4())[:8],
                "timestamp":   time.strftime("%H:%M:%S"),
                "type":        "etw_live",
                "file":        result.get("file", ""),
                "filename":    result.get("filename", ""),
                "verdict":     result.get("verdict", ""),
                "final_score": result.get("final_score"),
                "cpp_score":   result.get("cpp_score"),
                "ai_score":    result.get("ai_score"),
                "method":      result.get("method", ""),
            }
            
            _timeline_cache.append(history_item)
            
        except Exception:
            pass 

    while True:
        try:
            pipe = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_INBOUND,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None
            )
            
            win32pipe.ConnectNamedPipe(pipe, None)
            hr, data = win32file.ReadFile(pipe, 65536)
            
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
            
            event = json.loads(data.decode('utf-16le'))
            cmd = event.get("cmd", "")
            exe = event.get("exe", "")
            
            filepath = ""
            if cmd:
                parts = shlex.split(cmd.replace('\\', '/'))
                if parts:
                    filepath = parts[0].replace('/', '\\')
            
            if not filepath:
                filepath = exe
                
            if not filepath:
                continue
                
            filepath_low = filepath.lower()
            ext = os.path.splitext(filepath_low)[1]
            
            if ext in THREAT_EXTS and "windows\\system32" not in filepath_low and "windows\\syswow64" not in filepath_low:
                now = time.time()
                with _etw_cache_lock:
                    if now - _etw_cache.get(filepath_low, 0) > 60:
                        _etw_cache[filepath_low] = now
                        
                        # Submit to the restricted pool instead of spawning infinite threads!
                        _etw_pool.submit(_scan_and_cache, filepath)
                
        except Exception:
            time.sleep(0.05)
# Start the listener thread when FastAPI boots up
threading.Thread(target=_kernel_listener_loop, daemon=True, name="KernelListener").start()

async def _log_result(result: dict, scan_type: str, background_tasks: Optional[BackgroundTasks] = None):
    global _history_cache
    async with _history_lock:
        
        # Create the standardized event object
        history_item = {
            "id":          str(uuid.uuid4())[:8],
            "timestamp":   time.strftime("%H:%M:%S"),
            "type":        scan_type,
            "file":        result.get("file",""),
            "filename":    result.get("filename",""),
            "verdict":     result.get("verdict",""),
            "final_score": result.get("final_score"),
            "cpp_score":   result.get("cpp_score"),
            "ai_score":    result.get("ai_score"),
            "method":      result.get("method",""),
        }
        
        # 1. Update the traditional history table
        _history_cache.append(history_item)
        _history_cache = _history_cache[-500:]
        
        # 2. NEW: Instantly feed the Live ETW/System Dashboard Timeline!
        _timeline_cache.append(history_item)
        
        # Write to disk in the background for single files
        if scan_type == "file" and background_tasks:
            background_tasks.add_task(_save_history_to_disk)

# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/")
async def index(request: Request):
    # Modern FastAPI/Starlette syntax requires 'request' as a distinct parameter
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )

@app.post("/api/scan/file")
async def api_scan_file(payload: ScanPayload, background_tasks: BackgroundTasks):
    if not os.path.exists(payload.path):
        raise HTTPException(status_code=404, detail="File not found.")

    try:
        # Run blocking C++ bridge in a threadpool to keep server responsive
        result = await run_in_threadpool(scan_file, payload.path)
        await _log_result(result, "file", background_tasks)
        return result
    except Exception as e:
        log.error(f"File scan failed for {payload.path}: {e}")
        raise HTTPException(status_code=500, detail="Internal error occurred during the scan.")

@app.post("/api/scan/upload")
async def api_scan_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Upgrade 4: Memory-safe chunked uploads
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")

    safe_name = file.filename.replace("/", "").replace("\\", "")
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"av_upload_{uuid.uuid4().hex[:8]}_{safe_name}")
    
    try:
        async with aiofiles.open(temp_path, 'wb') as out_file:
            while content := await file.read(1024 * 1024): # Read in 1MB chunks
                await out_file.write(content)
        
        result = await run_in_threadpool(scan_file, temp_path)
        
        # Hide the temp path from the UI
        result['file'] = safe_name
        result['filename'] = safe_name
        
        await _log_result(result, "file", background_tasks)
        return result
        
    except Exception as e:
        log.error(f"Upload scan failed: {e}")
        raise HTTPException(status_code=500, detail="Internal error processing file.")
        
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

@app.post("/api/scan/folder")
async def api_scan_folder(payload: ScanPayload, background_tasks: BackgroundTasks):
    if _is_folder_scanning():
        raise HTTPException(status_code=409, detail="Folder scan already in progress")
        
    if not os.path.isdir(payload.path):
        raise HTTPException(status_code=400, detail="Invalid folder path")

    await _start_folder()

    # Upgrade 5: Native FastAPI StreamingResponse
    async def event_generator():
        try:
            clean_files_sent = 0  
            
            # Since scan_folder is likely a sync generator, we iterate through it 
            # We use an executor loop if it's blocking, but standard iteration is okay here if chunks are fast
            for result in scan_folder(payload.path):
                if _cancel_event.is_set(): 
                    log.info("Scan cancelled by user.")
                    break
                
                score = result.get("final_score") or 0
                
                if score > 0:
                    await _log_result(result, "folder")
                    yield f"data:{json.dumps(result)}\n\n"
                else:
                    if clean_files_sent < 2000:
                        clean_files_sent += 1
                        yield f"data:{json.dumps(result)}\n\n"
                    else:
                        heartbeat = {
                            "progress_only": True,
                            "progress": result.get("progress", {}),
                            "filename": result.get("filename", "Scanning...")
                        }
                        yield f"data:{json.dumps(heartbeat)}\n\n"
                        
                # Yield control back to the event loop so the server isn't choked
                await asyncio.sleep(0) 
                
            yield "data:{\"done\":true}\n\n"
            
        except asyncio.CancelledError:
            log.info("Client disconnected. Aborting folder scan.")
            _cancel_event.set()
        except Exception as e:
            log.error(f"Folder scan stream error: {e}")
            yield f"data:{json.dumps({'error': 'Stream interrupted.'})}\n\n"
        finally:
            await _end_folder()
            # Defer disk write to background task
            background_tasks.add_task(_save_history_to_disk)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache", 
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )

@app.post("/api/scan/stop")
async def api_scan_stop():
    _cancel_event.set()
    return {"status": "stop requested"}

@app.get("/api/history")
async def api_history():
    async with _history_lock:
        return _history_cache

@app.post("/api/history/clear")
async def api_history_clear(background_tasks: BackgroundTasks):
    global _history_cache
    async with _history_lock:
        _history_cache = []
        background_tasks.add_task(_save_history_to_disk)
    return {"status": "cleared"}

@app.post("/api/export")
async def api_export(results: List[Dict[str, Any]]):
    return JSONResponse(
        content=results,
        headers={
            "Content-Disposition": "attachment; filename=scan_results.json"
        }
    )

@app.get("/api/status")
async def api_status():
    model_path   = _HERE / "models" / "ember_lightgbm.txt"
    model_ok = model_path.exists()
            
    return {
        "scanning":      _is_folder_scanning(),
        "model_trained": model_ok,
        # ── PRODUCTION FIX: Tauri manages the C++ executable now ──
        "scanner_built": True, 
        "engine":        "EMBER 2018 (LightGBM)" if model_ok else "Offline",
        "model_meta":    {
            "feature_count": 2351, 
            "expected_features": 2351,
            "stale": False 
        } 
    }

@app.post("/api/dashboard/clear")
async def api_dashboard_clear():
    _timeline_cache.clear()
    return {"status": "cleared"}

# ── Live System Monitor (Phase 1: Fast IPC Integration) ───────────────────

@app.get("/api/dashboard/timeline")
async def get_event_timeline():
    """
    Get real-time scan events for the dashboard visualization directly from the IPC cache.
    Zero-blocking, no Admin rights required.
    """
    events = list(_timeline_cache)
    
    # Map 'HIGH RISK' (from bridge.py) to 'MALICIOUS' for the UI styling
    for e in events:
        if e.get("verdict") == "HIGH RISK":
            e["verdict"] = "MALICIOUS"
            
    return {
        "timeline": events,
        "summary": {
            "total_events": len(events),
            "by_verdict": {
                "CLEAN": sum(1 for e in events if e.get("verdict") == "CLEAN"),
                "SUSPICIOUS": sum(1 for e in events if e.get("verdict") == "SUSPICIOUS"),
                "MALICIOUS": sum(1 for e in events if e.get("verdict") == "MALICIOUS"),
            }
        }
    }

# ── BOTTOM LAUNCHER ───────────────────────────────────────────────────────
if __name__ == "__main__":
    # Prevents infinite spawn crash in packaged Windows apps
    multiprocessing.freeze_support()
    
    import uvicorn
    print("\n  [HeuristicScanner AI Started] — http://localhost:5000\n")
    
    # PRODUCTION FIX: Pass the 'app' object directly, no quotes!
    uvicorn.run(app, host="0.0.0.0", port=5000)