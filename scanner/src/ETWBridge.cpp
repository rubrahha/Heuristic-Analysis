extern "C" {
    #include "platform/windows/ETWConsumer.h"
    
    // Opaque handle pattern (from your enterprise guidelines)
    typedef Platform::ETW::Consumer ETWConsumerHandle;
    
    __declspec(dllexport) void* ETW_CreateConsumer() {
        return new ETWConsumerHandle();
    }
    
    __declspec(dllexport) bool ETW_Start(void* handle, const wchar_t* provider) {
        auto consumer = reinterpret_cast<ETWConsumerHandle*>(handle);
        return consumer->Start(provider);
    }
    
    __declspec(dllexport) bool ETW_GetNextEvent(void* handle, int* eventID, wchar_t* outData) {
        auto consumer = reinterpret_cast<ETWConsumerHandle*>(handle);
        Platform::ETW::Event evt;
        if (consumer->GetNextEvent(evt)) {
            *eventID = evt.eventID;
            // Copy evt.data to outData (JSON format)
            return true;
        }
        return false;
    }
    
    __declspec(dllexport) void ETW_Stop(void* handle) {
        auto consumer = reinterpret_cast<ETWConsumerHandle*>(handle);
        consumer->Stop();
    }
    
    __declspec(dllexport) void ETW_DestroyConsumer(void* handle) {
        delete reinterpret_cast<ETWConsumerHandle*>(handle);
    }
}