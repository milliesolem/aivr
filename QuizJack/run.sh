#!/usr/bin/env bash
# QuizJack PoC runner
set -euo pipefail
cd "$(dirname "$0")"
echo "== QuizJack: ClassQuiz captcha bypass + predictable PINs =="
python3 poc.py
