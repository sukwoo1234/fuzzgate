// V2.5 ONNX coverage harness.
//
// Loads each model file through Ort::Session creation, exercising onnxruntime's
// model parse / load / graph-build / optimizer code paths under LLVM source
// coverage instrumentation. Unlike the existing black-box libfuzzer driver
// (which shells out to a separate, uninstrumented process), this binary links
// the *instrumented* libonnxruntime.so directly, so coverage flows into
// onnxruntime itself.
//
// It intentionally does NOT run inference: input-tensor synthesis is model-
// specific and would add nondeterminism without materially widening coverage of
// the loader, which is this PoC's focus. Malformed/unsupported models are
// expected and counted, not fatal -- the load path is covered either way.
//
// V2.5 coverage measurement contract:
//  - SessionOptions pinned single-threaded (intra=inter=1) for determinism.
//  - GraphOptimizationLevel selectable via ONNX_COV_OPT_LEVEL (default ENABLE_ALL)
//    for the optimizer-level sensitivity sweep.
//  - Per-input machine-readable JSON record on stdout: path, bytes, session_ok,
//    parse_ok (best-effort), error. The experiment runner invokes this binary ONCE
//    per input so each process writes its own LLVM_PROFILE_FILE -> per-input profraw
//    separation -> order-independent union + per-input set-difference.
//  - parse_ok distinguishes "reached graph build" from "died at protobuf parse",
//    allowing analysis to separate parse failures from graph-build outcomes. The raw
//    error message is emitted verbatim so analysis can refine the classification.
#include <onnxruntime_cxx_api.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::string json_escape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default: {
        unsigned char uc = static_cast<unsigned char>(c);
        // Escape control bytes AND any non-ASCII byte (>=0x7f). ONNX error messages on
        // corrupted models can echo raw model bytes, which would otherwise emit invalid
        // UTF-8 and break downstream JSON parsing. Emitting \u00XX keeps stdout pure ASCII.
        if (uc < 0x20 || uc >= 0x7f) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(uc));
          o += buf;
        } else {
          o += c;
        }
      }
    }
  }
  return o;
}

// Best-effort: did the model get PAST protobuf parsing into graph build?
// onnxruntime throws "...Protobuf parsing failed..." when the wire bytes do not
// decode as a ModelProto. A post-parse failure (unsupported op, shape/type error,
// missing graph) means the parser WAS reached. The raw message is recorded in the
// JSON so the frozen analysis can refine this rule on the messages actually observed.
static bool looks_parse_failed(const std::string& msg) {
  return msg.find("Protobuf parsing failed") != std::string::npos;
}

static GraphOptimizationLevel graph_opt_level_from_env() {
  const char* e = std::getenv("ONNX_COV_OPT_LEVEL");
  if (e == nullptr) return ORT_ENABLE_ALL;
  if (std::strcmp(e, "DISABLE_ALL") == 0 || std::strcmp(e, "0") == 0) return ORT_DISABLE_ALL;
  if (std::strcmp(e, "BASIC") == 0 || std::strcmp(e, "1") == 0) return ORT_ENABLE_BASIC;
  if (std::strcmp(e, "EXTENDED") == 0 || std::strcmp(e, "2") == 0) return ORT_ENABLE_EXTENDED;
  return ORT_ENABLE_ALL;  // default + "ENABLE_ALL"/"3"
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <model.onnx> [<model.onnx> ...]\n", argv[0]);
    return 2;
  }

  Ort::Env env(ORT_LOGGING_LEVEL_FATAL, "onnx_cov_harness");
  const GraphOptimizationLevel opt = graph_opt_level_from_env();

  int loaded = 0, failed = 0;
  for (int i = 1; i < argc; ++i) {
    const char* path = argv[i];
    std::ifstream f(path, std::ios::binary);
    bool session_ok = false;
    bool parse_ok = false;
    std::string err;
    long long nbytes = -1;

    if (!f) {
      err = "cannot open file";  // parse_ok stays false
    } else {
      std::vector<char> buf((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
      nbytes = static_cast<long long>(buf.size());

      Ort::SessionOptions opts;
      opts.SetIntraOpNumThreads(1);  // determinism: single-threaded
      opts.SetInterOpNumThreads(1);
      opts.SetGraphOptimizationLevel(opt);
      try {
        Ort::Session session(env, buf.data(), buf.size(), opts);
        session_ok = true;
        parse_ok = true;  // fully constructed -> parsed
      } catch (const std::exception& e) {
        err = e.what();
        parse_ok = !looks_parse_failed(err);  // reached graph build unless proto-parse died
      }
    }

    if (session_ok) {
      ++loaded;
    } else {
      ++failed;
    }
    // One JSON record per input on stdout. The experiment runner calls this binary
    // once per input, so each record corresponds to exactly one process / profraw.
    std::printf(
        "{\"path\":\"%s\",\"bytes\":%lld,\"session_ok\":%s,\"parse_ok\":%s,\"error\":\"%s\"}\n",
        json_escape(path).c_str(), nbytes, session_ok ? "true" : "false",
        parse_ok ? "true" : "false", json_escape(err).c_str());
  }

  std::fprintf(stderr, "[onnx_cov_harness] loaded=%d failed=%d total=%d\n", loaded,
               failed, argc - 1);
  return 0;
}
