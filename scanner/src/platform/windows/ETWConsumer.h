#pragma once

// MUST be included before Windows headers to prevent macro conflicts
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h> // Defines TRACEHANDLE

#include <string>
#include <functional>
#include <queue>
#include <mutex>

namespace Platform::ETW {

    struct Event {
        int eventID;
        std::wstring timestamp;
        std::wstring data[4];  // filePath, verdict, indicators, etc.
    };

    class Consumer {
    public:
        Consumer();
        ~Consumer();

        // Start listening to your ETW provider
        bool Start(const wchar_t* providerName);
        void Stop();

        // Get next event (non-blocking)
        bool GetNextEvent(Event& outEvent);

        // Check if running
        bool IsRunning() const;

    private:
        TRACEHANDLE m_sessionHandle;
        TRACEHANDLE m_traceHandle;
        std::queue<Event> m_eventQueue;
        std::mutex m_queueLock;
        bool m_isRunning;
    };
}