
  HeuristicScanner v2.0
  ================================================

  STRUCTURE
  ---------
  HeuristicScanner\
    scanner\              C++ heuristic engine  (open in Visual Studio 2019)
      CMakeLists.txt
      src\
        main.cpp
        core\             ScanTarget.h, ScanResult.h
        heuristics\       11 detection rules + PEParser.h
        platform\windows\ FileSystem.h/.cpp, Registry.h/.cpp
        utils\            StringUtils.h
    ai\                   Python AI + Web UI  (open in VS Code)
      app.py              Flask web server
      bridge.py           C++ <-> AI bridge
      extractor.py        35 PE features
      train.py            XGBoost training
      templates\          Browser UI (index.html)
      dataset\malware\    PUT MALWARE SAMPLES HERE
      dataset\clean\      PUT CLEAN .EXE FILES HERE
      models\             model.pkl saved here after training
      logs\               scan history
    setup.bat             Run ONCE
    build.bat             Rebuild C++ (when you change C++ code)
    train.bat             Train AI model
    run.bat               Start scanner (run every day)
    HeuristicScanner.code-workspace  Open in VS Code

  FIRST TIME (do once)
  --------------------
  1. Extract zip to C:\HeuristicScanner
  2. Double-click setup.bat
  3. Open Visual Studio 2019
       File > Open > CMake...
       Select: scanner\CMakeLists.txt
       Press Ctrl+Shift+B  (builds HeuristicScanner.exe)
  4. Add samples:
       Malware .exe → ai\dataset\malware\
       Clean .exe   → ai\dataset\clean\   (copy from C:\Windows\System32)
  5. Double-click train.bat
  6. Double-click run.bat → browser opens at http://localhost:5000

  EVERY DAY
  ---------
  Double-click run.bat. That's it.

  SCORE THRESHOLDS
  ----------------
   0–19   CLEAN
  20–49   LOW RISK
  50–79   SUSPICIOUS
  80–100  HIGH RISK

  11 DETECTION RULES
  ------------------
  EntropyRule        High Shannon entropy → packed/encrypted content
  SectionRule        W+X sections, packer names, high-entropy exec sections
  ImportTableRule    Injection triad, keylogger, credential, crypto, C2 APIs
  PEHeaderRule       Tampered timestamps, no ASLR/DEP, EP outside .text
  StringAnalysisRule Anti-VM strings, offensive tools, PS downloader, C2 domains
  OverlayRule        Embedded PE/archive or high-entropy appended data
  FileTypeRule       Extension/magic mismatch, double extensions
  LocationRule       Temp/AppData/Startup = risky; System32 = trusted
  AgeRule            Recently dropped files in high-risk locations
  SignatureRule      Known packer bytes, shell command strings
  PersistenceRule    Registry Run key auto-start persistence
