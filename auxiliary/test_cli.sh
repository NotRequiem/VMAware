#!/usr/bin/env bash
# CLI argument test suite for VMAware

set -euo pipefail

BIN="${1:-build/vmaware}"

if [[ ! -x "$BIN" ]]; then
    echo "Binary not found or not executable: $BIN"
    exit 1
fi

pass=0
fail=0

ok()   { echo "  PASS  $1"; pass=$((pass + 1)); }
fail() { echo "  FAIL  $1"; fail=$((fail + 1)); }

check() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        ok "$desc"
    else
        fail "$desc"
    fi
}

check_fails() {
    local desc="$1"; shift
    if ! "$@" &>/dev/null; then
        ok "$desc"
    else
        fail "$desc"
    fi
}

# Uses regex matching to prevent SIGPIPE/Broken pipe with pipefail
# and suppresses stderr so debug logs don't pollute the return value
match() {
    local desc="$1" pattern="$2"; shift 2
    local out
    out=$("$@" 2>/dev/null) || { fail "$desc (non-zero exit)"; return; }
    if [[ "$out" =~ $pattern ]]; then
        ok "$desc"
    else
        local first_line
        first_line="$(printf '%s\n' "$out" | head -n 1)"
        fail "$desc  (got: $first_line)"
    fi
}

range() {
    local desc="$1" lo="$2" hi="$3"; shift 3
    local out
    out=$("$@" 2>/dev/null) || { fail "$desc (non-zero exit)"; return; }
    if [[ "$out" =~ ^[0-9]+$ ]] && (( out >= lo && out <= hi )); then
        ok "$desc"
    else
        fail "$desc  (got: $out, expected $lo–$hi)"
    fi
}

echo "=== vmaware CLI tests ==="
echo

# exit codes
echo "exit codes"
check       "--help exits 0"             "$BIN" --help
check       "--version exits 0"          "$BIN" --version
check       "--brand-list exits 0"       "$BIN" --brand-list
check       "--detect exits 0"           "$BIN" --detect
check       "--percent exits 0"          "$BIN" --percent
check       "--brand exits 0"            "$BIN" --brand
check       "--type exits 0"             "$BIN" --type
check       "--conclusion exits 0"       "$BIN" --conclusion
check       "--number exits 0"           "$BIN" --number
check       "--stdout exits 0 or 1"      bash -c '"$1" --stdout; [[ $? -le 1 ]]' _ "$BIN"
check_fails "unknown arg exits non-zero" "$BIN" --this-arg-does-not-exist

# short-flag aliases
echo
echo "short flag aliases"
check "-h exits 0"   "$BIN" -h
check "-v exits 0"   "$BIN" -v
check "-a exits 0"   "$BIN" -a --detect
check "-d exits 0"   "$BIN" -d
check "-b exits 0"   "$BIN" -b
check "-p exits 0"   "$BIN" -p
check "-c exits 0"   "$BIN" -c
check "-n exits 0"   "$BIN" -n
check "-t exits 0"   "$BIN" -t
check "-l exits 0"   "$BIN" -l

# output format
echo
echo "output format"
match   "--detect outputs 0 or 1"          "^[01]$"        "$BIN" --detect
range   "--percent outputs 0-100"          0 100           "$BIN" --percent
match   "--number outputs a positive int"  "^[1-9][0-9]*$" "$BIN" --number
match   "--brand outputs a non-empty line" "."             "$BIN" --brand
match   "--type outputs a non-empty line"  "."             "$BIN" --type
match   "--conclusion outputs a sentence"  "."             "$BIN" --conclusion

# no-ansi strips escape codes (uses portable Bash string comparison without grep -P)
echo
echo "no-ansi"
out=$("$BIN" --no-ansi 2>/dev/null)
if [[ "$out" == *$'\033['* ]]; then
    fail "--no-ansi still contains ANSI escape codes"
else
    ok "--no-ansi output contains no ANSI escape codes"
fi

# --number sanity (matches technique count)
echo
echo "technique count"
n=$("$BIN" --number 2>/dev/null)
if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 10 )); then
    ok "--number returns plausible technique count ($n)"
else
    fail "--number returned unexpected value: $n"
fi

# mutual exclusion
echo
echo "mutual exclusion"
check_fails "--detect + --brand rejected"   "$BIN" --detect --brand
check_fails "--percent + --brand rejected"  "$BIN" --percent --brand
check_fails "--stdout + --detect rejected"  "$BIN" --stdout --detect

# --disable: valid names
echo
echo "--disable (valid names)"
check "--disable single name works"               "$BIN" --disable HYPERVISOR_BIT --detect
check "--disable multiple space-sep names works"  "$BIN" --disable HYPERVISOR_BIT NVRAM QEMU_USB --detect
check "--disable comma-separated names works"     "$BIN" --disable HYPERVISOR_BIT,NVRAM --detect
check "--disable mixed comma+space works"         "$BIN" --disable HYPERVISOR_BIT, NVRAM, QEMU_USB --detect
check "--disable UD works"                        "$BIN" --disable UD --detect

# --disable: invalid names
echo
echo "--disable (invalid names)"
check_fails "--disable bogus name fails"          "$BIN" --disable NOT_A_REAL_TECHNIQUE --detect
check_fails "--disable MULTIPLE (setting) fails"  "$BIN" --disable MULTIPLE --detect

# --disable visible in general output
echo
echo "--disable reflected in general output"
out=$("$BIN" --no-ansi --disable HYPERVISOR_BIT 2>/dev/null)
if [[ "$out" == *"Skipped CPUID hypervisor bit"* ]] || [[ "$out" == *"HYPERVISOR_BIT"* && "$out" == *"Skipped"* ]]; then
    ok "--disable HYPERVISOR_BIT shows as skipped in general output"
else
    fail "--disable HYPERVISOR_BIT not reflected in general output"
fi

# --high-threshold
echo
echo "--high-threshold"
p_normal=$("$BIN" --percent 2>/dev/null)
p_high=$(  "$BIN" --percent --high-threshold 2>/dev/null)
if [[ "$p_normal" =~ ^[0-9]+$ ]] && [[ "$p_high" =~ ^[0-9]+$ ]] && (( p_normal >= p_high )); then
    ok "--high-threshold produces equal or lower percentage ($p_normal -> $p_high)"
else
    fail "--high-threshold produced higher percentage ($p_normal -> $p_high)"
fi

# --all
echo
echo "--all"
check "--all --detect exits 0"   "$BIN" --all --detect
check "--all --percent exits 0"  "$BIN" --all --percent

# --dynamic
echo
echo "--dynamic"
check "--dynamic --conclusion exits 0" "$BIN" --dynamic --conclusion

# --json
echo
echo "--json"
tmpjson=$(mktemp /tmp/vmaware_test_XXXXXX.json)
trap 'rm -f "$tmpjson"' EXIT
if "$BIN" --json --output "$tmpjson" 2>/dev/null && [[ -s "$tmpjson" ]]; then
    ok "--json creates a non-empty output file"
else
    fail "--json did not create an output file"
fi
if grep -q '"is_detected"' "$tmpjson" 2>/dev/null; then
    ok "--json output contains expected keys"
else
    fail "--json output missing expected keys"
fi

# --brand-list
echo
echo "--brand-list"
count=$("$BIN" --brand-list 2>/dev/null | wc -l | tr -d ' ')
if (( count > 5 )); then
    ok "--brand-list returns multiple entries ($count lines)"
else
    fail "--brand-list returned too few entries ($count lines)"
fi

# summary
echo
echo "==========================="
echo "  Passed: $pass"
echo "  Failed: $fail"
echo "==========================="
(( fail == 0 ))