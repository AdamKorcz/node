#pragma once
#include <string>
#include <string_view>

// Minimal numbered placeholder formatter: replaces {0}, {1}, ... with strings.
// Dependency-free and perfect for short JS templates.
inline void ReplaceAll_(std::string& s, std::string_view from, std::string_view to) {
  if (from.empty()) return;
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
}

template <typename... StrLike>
std::string FormatJs(std::string_view tmpl, const StrLike&... vals) {
  std::string out(tmpl);
  std::string args[] = { std::string(vals)... };
  for (size_t i = 0; i < std::size(args); ++i) {
    std::string needle = "{" + std::to_string(i) + "}";
    ReplaceAll_(out, needle, args[i]);
  }
  return out;
}

// Escape a *single-quoted* JS string literal (returns with quotes included).
inline std::string ToSingleQuotedJsLiteral(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\'': out += "\\\'"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\f': out += "\\f"; break;
      case '\b': out += "\\b"; break;
      default:
        if (c < 0x20) {
          char buf[5];
          snprintf(buf, sizeof(buf), "\\x%02X", static_cast<int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('\'');
  return out;
}

// Escape a *double-quoted* JS string literal (returns with quotes included).
inline std::string ToDoubleQuotedJsLiteral(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\f': out += "\\f"; break;
      case '\b': out += "\\b"; break;
      default:
        if (c < 0x20) {
          char buf[5];
          snprintf(buf, sizeof(buf), "\\x%02X", static_cast<int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
  return out;
}
