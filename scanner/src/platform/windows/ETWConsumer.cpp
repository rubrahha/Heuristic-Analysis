#include "ETWConsumer.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Platform::ETW {

    Consumer::Consumer()
        : m_sessionHandle(0), m_traceHandle(0), m_isRunning(false) {
    } // Changed NULL to 0 (TRACEHANDLE is an integer)

    Consumer::~Consumer() {
        Stop();
    }

    bool Consumer::Start(const wchar_t* providerName) {
        // Minimal implementation - full version needs event tracing setup
        m_isRunning = true;
        return true;
    }

    void Consumer::Stop() {
        m_isRunning = false;
    }

    bool Consumer::GetNextEvent(Event& outEvent) {
        std::lock_guard<std::mutex> lock(m_queueLock);
        if (m_eventQueue.empty()) {
            return false;
        }
        outEvent = m_eventQueue.front();
        m_eventQueue.pop();
        return true;
    }

    bool Consumer::IsRunning() const {
        return m_isRunning;
    }
}