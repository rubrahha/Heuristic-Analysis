#include "ScanResult.h"
#include "../utils/StringUtils.h"
#include <sstream>
#include <algorithm>

namespace Core {

    void ScanResult::Finalize() {
        // ── 1. Deduplicate Indicators ─────────────────────────────────────────
        // Highly modular engines often produce overlapping contextual strings.
        // We sort and erase duplicates to keep the JSON payload clean and professional.
        if (!indicators.empty()) {
            std::ranges::sort(indicators);
            auto uniqueEnd = std::ranges::unique(indicators);
            indicators.erase(uniqueEnd.begin(), uniqueEnd.end());
        }

        // ── 2. Assign Threat Verdict ──────────────────────────────────────────
        // Standard Incident Response Tiers
        if (riskScore >= 75) {
            verdict = "MALICIOUS";
        }
        else if (riskScore >= 45) {
            verdict = "SUSPICIOUS";
        }
        else if (riskScore >= 20) {
            verdict = "ANOMALOUS";
        }
        else {
            verdict = "CLEAN";
        }
    }

    // Enterprise Standard: Manual JSON serialization
    std::string ScanResult::ToJson() const {
        std::ostringstream json;

        // Safely convert the Unicode std::filesystem::path to a UTF-8 string
        //std::string safePath = Utils::WstrToStr(target.filePath.wstring());
        std::string safePath = Utils::WstrToStr(targetPath.wstring());

        json << "{\"path\":\"" << EscapeJsonString(safePath) << "\",";
        json << "\"score\":" << riskScore << ",";
        json << "\"verdict\":\"" << verdict << "\",";
        json << "\"scan_ms\":" << scanDuration.count() << ",";

        // Serialize Indicators Array
        json << "\"indicators\":[";
        for (size_t i = 0; i < indicators.size(); ++i) {
            json << "\"" << EscapeJsonString(indicators[i]) << "\"";
            if (i < indicators.size() - 1) {
                json << ",";
            }
        }
        json << "],";

        // Serialize Rule Contributions Map
        json << "\"rules\":{";
        size_t ruleIdx = 0;
        for (const auto& [ruleName, ruleScore] : ruleContributions) {
            json << "\"" << EscapeJsonString(ruleName) << "\":" << ruleScore;
            if (ruleIdx < ruleContributions.size() - 1) {
                json << ",";
            }
            ruleIdx++;
        }
        json << "}}";

        return json.str();
    }

    std::string ScanResult::EscapeJsonString(const std::string& input) {
        std::string output;
        output.reserve(input.length() * 1.2); // Pre-allocate space for escaped characters

        for (char c : input) {
            switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b";  break;
            case '\f': output += "\\f";  break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            default:
                // Escape unprintable control characters to prevent JSON corruption
                if ('\x00' <= c && c <= '\x1f') {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", c);
                    output += hex;
                }
                else {
                    output += c;
                }
            }
        }
        return output;
    }

} // namespace Core