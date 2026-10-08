#ifndef TOOL_HARNESSES_COMMON_MODEL_BUNDLE_H_
#define TOOL_HARNESSES_COMMON_MODEL_BUNDLE_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tool::model_bundle {

inline constexpr std::uint8_t kMagic[8] = {'F', 'Z', 'B', 'N', 'D', 'L', '1', 0};
inline constexpr std::size_t kMaxBundleBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kMaxEntries = 64;
inline constexpr std::size_t kMaxNameBytes = 240;
inline constexpr std::size_t kMaxNameDepth = 8;

struct EntryView {
  std::string_view name;
  const std::uint8_t* data;
  std::size_t size;
};

struct EntryInput {
  std::string_view name;
  std::string_view data;
};

inline bool Fail(std::string* error, std::string message) {
  if (error != nullptr) {
    *error = std::move(message);
  }
  return false;
}

inline bool ValidateName(std::string_view name, std::string* error) {
  if (name.empty() || name.size() > kMaxNameBytes) {
    return Fail(error, "FZB1 entry name length must be 1..240 bytes");
  }
  std::size_t depth = 0;
  std::size_t start = 0;
  while (start <= name.size()) {
    const std::size_t slash = name.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? name.size() : slash;
    const std::string_view segment = name.substr(start, end - start);
    if (segment.empty() || segment == "." || segment == "..") {
      return Fail(error, "FZB1 entry name contains a non-canonical segment");
    }
    ++depth;
    if (depth > kMaxNameDepth) {
      return Fail(error, "FZB1 entry name depth exceeds 8");
    }
    for (const char character : segment) {
      const auto byte = static_cast<unsigned char>(character);
      const bool alpha = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
      const bool digit = byte >= '0' && byte <= '9';
      if (!alpha && !digit && byte != '_' && byte != '.' && byte != '-') {
        return Fail(error, "FZB1 entry name contains a forbidden byte");
      }
    }
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
  }
  return true;
}

inline bool Read(const std::uint8_t* data, std::size_t size, std::size_t* offset,
                 std::size_t length, const std::uint8_t** value, std::string* error,
                 const char* label) {
  if (length > size || *offset > size - length) {
    return Fail(error, std::string("truncated FZB1 ") + label);
  }
  *value = data + *offset;
  *offset += length;
  return true;
}

inline std::uint16_t LoadLe16(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) |
                                    static_cast<std::uint16_t>(bytes[1]) << 8);
}

inline std::uint32_t LoadLe32(const std::uint8_t* bytes) {
  std::uint32_t value = 0;
  for (unsigned shift = 0; shift < 32; shift += 8) {
    value |= static_cast<std::uint32_t>(bytes[shift / 8]) << shift;
  }
  return value;
}

inline std::uint64_t LoadLe64(const std::uint8_t* bytes) {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(bytes[shift / 8]) << shift;
  }
  return value;
}

inline bool Decode(const std::uint8_t* data, std::size_t size,
                   std::vector<EntryView>* entries, std::string* error) {
  if (entries == nullptr) {
    return Fail(error, "FZB1 output entry vector is null");
  }
  entries->clear();
  if (data == nullptr && size != 0) {
    return Fail(error, "FZB1 input pointer is null for non-empty input");
  }
  if (size > kMaxBundleBytes) {
    return Fail(error, "FZB1 input exceeds the 64 MiB limit");
  }
  std::size_t offset = 0;
  const std::uint8_t* field = nullptr;
  if (!Read(data, size, &offset, sizeof(kMagic), &field, error, "magic")) {
    return false;
  }
  if (!std::equal(std::begin(kMagic), std::end(kMagic), field)) {
    return Fail(error, "invalid FZB1 magic");
  }
  if (!Read(data, size, &offset, 4, &field, error, "entry count")) {
    return false;
  }
  const std::size_t count = LoadLe32(field);
  if (count == 0 || count > kMaxEntries) {
    return Fail(error, "FZB1 entry count must be 1..64");
  }
  entries->reserve(count);

  std::string_view previous;
  std::set<std::string_view> seen_names;
  for (std::size_t index = 0; index < count; ++index) {
    if (!Read(data, size, &offset, 2, &field, error, "entry name length")) {
      entries->clear();
      return false;
    }
    const std::size_t name_size = LoadLe16(field);
    if (!Read(data, size, &offset, 8, &field, error, "entry data length")) {
      entries->clear();
      return false;
    }
    const std::uint64_t data_size_u64 = LoadLe64(field);
    if (data_size_u64 > std::numeric_limits<std::size_t>::max()) {
      entries->clear();
      return Fail(error, "FZB1 entry data length does not fit size_t");
    }
    if (!Read(data, size, &offset, name_size, &field, error, "entry name")) {
      entries->clear();
      return false;
    }
    const std::string_view name(reinterpret_cast<const char*>(field), name_size);
    if (!ValidateName(name, error)) {
      entries->clear();
      return false;
    }
    if (!previous.empty() && name <= previous) {
      entries->clear();
      return Fail(error, name == previous ? "duplicate FZB1 entry name"
                                          : "FZB1 entries are not in canonical byte order");
    }
    for (std::size_t slash = name.find('/'); slash != std::string_view::npos;
         slash = name.find('/', slash + 1)) {
      if (seen_names.count(name.substr(0, slash)) != 0) {
        entries->clear();
        return Fail(error, "FZB1 entry names conflict as file and directory");
      }
    }
    const std::size_t data_size = static_cast<std::size_t>(data_size_u64);
    if (!Read(data, size, &offset, data_size, &field, error, "entry data")) {
      entries->clear();
      return false;
    }
    entries->push_back(EntryView{name, field, data_size});
    previous = name;
    seen_names.insert(name);
  }
  if (offset != size) {
    entries->clear();
    return Fail(error, "trailing bytes after the final FZB1 entry");
  }
  return true;
}

inline bool DecodeWithAllowlist(const std::uint8_t* data, std::size_t size,
                                const std::vector<std::string_view>& allowlist,
                                std::vector<EntryView>* entries, std::string* error) {
  if (allowlist.empty() || allowlist.size() > kMaxEntries) {
    return Fail(error, "FZB1 allowlist size must be 1..64");
  }
  std::set<std::string_view> allowed;
  for (const std::string_view name : allowlist) {
    if (!ValidateName(name, error)) {
      return false;
    }
    if (!allowed.insert(name).second) {
      return Fail(error, "duplicate FZB1 allowlist entry");
    }
  }
  if (!Decode(data, size, entries, error)) {
    return false;
  }
  std::set<std::string_view> actual;
  for (const EntryView& entry : *entries) {
    actual.insert(entry.name);
  }
  if (actual != allowed) {
    entries->clear();
    return Fail(error, "FZB1 entries do not match target allowlist");
  }
  return true;
}

inline bool AppendLe(std::vector<std::uint8_t>* output, std::uint64_t value,
                     unsigned bytes) {
  if (output == nullptr || bytes > sizeof(value)) {
    return false;
  }
  for (unsigned index = 0; index < bytes; ++index) {
    output->push_back(static_cast<std::uint8_t>(value >> (index * 8)));
  }
  return true;
}

inline bool Encode(const std::vector<EntryInput>& input,
                   std::vector<std::uint8_t>* output, std::string* error) {
  if (output == nullptr) {
    return Fail(error, "FZB1 output byte vector is null");
  }
  if (input.empty() || input.size() > kMaxEntries) {
    return Fail(error, "FZB1 entry count must be 1..64");
  }
  std::vector<EntryInput> ordered = input;
  for (const EntryInput& entry : ordered) {
    if (!ValidateName(entry.name, error)) {
      return false;
    }
  }
  std::sort(ordered.begin(), ordered.end(), [](const EntryInput& left, const EntryInput& right) {
    return left.name < right.name;
  });
  std::size_t total = sizeof(kMagic) + 4;
  std::set<std::string_view> seen_names;
  for (const EntryInput& entry : ordered) {
    if (!seen_names.insert(entry.name).second) {
      return Fail(error, "duplicate FZB1 entry name");
    }
    for (std::size_t slash = entry.name.find('/'); slash != std::string_view::npos;
         slash = entry.name.find('/', slash + 1)) {
      if (seen_names.count(entry.name.substr(0, slash)) != 0) {
        return Fail(error, "FZB1 entry names conflict as file and directory");
      }
    }
    if (entry.name.size() > kMaxBundleBytes - total ||
        entry.data.size() > kMaxBundleBytes - total - entry.name.size() ||
        10 > kMaxBundleBytes - total - entry.name.size() - entry.data.size()) {
      return Fail(error, "FZB1 output exceeds the 64 MiB limit");
    }
    total += 10 + entry.name.size() + entry.data.size();
  }
  // EntryInput is a view type, so a caller may intentionally re-encode slices of
  // *output. Build separately and replace output only after every view has been read.
  std::vector<std::uint8_t> encoded;
  encoded.reserve(total);
  encoded.insert(encoded.end(), std::begin(kMagic), std::end(kMagic));
  if (!AppendLe(&encoded, ordered.size(), 4)) {
    return Fail(error, "invalid internal FZB1 count width");
  }
  for (const EntryInput& entry : ordered) {
    if (!AppendLe(&encoded, entry.name.size(), 2) ||
        !AppendLe(&encoded, entry.data.size(), 8)) {
      return Fail(error, "invalid internal FZB1 entry width");
    }
    encoded.insert(encoded.end(), entry.name.begin(), entry.name.end());
    encoded.insert(encoded.end(), entry.data.begin(), entry.data.end());
  }
  *output = std::move(encoded);
  return true;
}

}  // namespace tool::model_bundle

#endif  // TOOL_HARNESSES_COMMON_MODEL_BUNDLE_H_
