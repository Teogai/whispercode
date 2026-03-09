#!/usr/bin/env bash
#
# verify-apk.sh — Verify a WhisperCode APK was built from source
#
# Usage: ./scripts/verify-apk.sh <path-to-apk> [--build-frontend]
#
# Checks:
#   1. APK structure — no unexpected files
#   2. AndroidManifest — no injected permissions/components
#   3. Native libraries — expected .so files, no rogue dependencies
#   4. DEX classes — no unexpected packages (ad SDKs, trackers, etc.)
#   5. Frontend assets — optionally diff against source build
#   6. Signing certificate — report signer identity
#
# Requirements: unzip, xmlstarlet or aapt2 (optional), readelf (optional),
#               baksmali or dexdump (optional), apksigner or keytool (optional)
#
# Exit code: 0 = all checks passed, 1 = warnings/failures found

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS=0
WARN=0
FAIL=0

pass()  { ((PASS++)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn()  { ((WARN++)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
fail()  { ((FAIL++)); echo -e "  ${RED}[FAIL]${NC} $1"; }
info()  { echo -e "  ${CYAN}[INFO]${NC} $1"; }
header() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# --- Args ---
APK_PATH="${1:-}"
BUILD_FRONTEND=false

if [[ "$APK_PATH" == "" ]]; then
    echo "Usage: $0 <path-to-apk> [--build-frontend]"
    echo ""
    echo "Options:"
    echo "  --build-frontend  Build frontend from source and compare with APK assets"
    exit 1
fi

shift
for arg in "$@"; do
    case "$arg" in
        --build-frontend) BUILD_FRONTEND=true ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

if [[ ! -f "$APK_PATH" ]]; then
    echo "Error: APK file not found: $APK_PATH"
    exit 1
fi

APK_PATH="$(realpath "$APK_PATH")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Verifying APK: $APK_PATH"
echo "Work directory: $WORK_DIR"

# ============================================================================
# CHECK 1: APK Structure
# ============================================================================
header "1. APK Structure Analysis"

unzip -q "$APK_PATH" -d "$WORK_DIR/apk"

# List all files in the APK
find "$WORK_DIR/apk" -type f | sed "s|$WORK_DIR/apk/||" | sort > "$WORK_DIR/file_list.txt"
TOTAL_FILES=$(wc -l < "$WORK_DIR/file_list.txt")
info "Total files in APK: $TOTAL_FILES"

# Define expected top-level entries for a Tauri Android APK
EXPECTED_TOPS="AndroidManifest.xml classes.dex lib assets res resources.arsc META-INF"

# Check for unexpected top-level entries
ACTUAL_TOPS=$(ls "$WORK_DIR/apk/" | sort)
UNEXPECTED=""
for entry in $ACTUAL_TOPS; do
    FOUND=false
    for expected in $EXPECTED_TOPS; do
        if [[ "$entry" == "$expected" || "$entry" == classes*.dex ]]; then
            FOUND=true
            break
        fi
    done
    if [[ "$FOUND" == "false" ]]; then
        UNEXPECTED="$UNEXPECTED $entry"
    fi
done

if [[ -z "$UNEXPECTED" ]]; then
    pass "No unexpected top-level entries"
else
    fail "Unexpected top-level entries:$UNEXPECTED"
fi

# Check for suspicious file types
SUSPICIOUS_EXTS=".sh .py .rb .pl .bat .cmd .ps1 .vbs .js.map"
SUSPICIOUS_FILES=""
while IFS= read -r f; do
    for ext in $SUSPICIOUS_EXTS; do
        if [[ "$f" == *"$ext" ]]; then
            SUSPICIOUS_FILES="$SUSPICIOUS_FILES\n    $f"
        fi
    done
done < "$WORK_DIR/file_list.txt"

if [[ -z "$SUSPICIOUS_FILES" ]]; then
    pass "No suspicious file types found"
else
    warn "Suspicious files found:$SUSPICIOUS_FILES"
fi

# Check lib/ directory for expected architectures
if [[ -d "$WORK_DIR/apk/lib" ]]; then
    ARCHS=$(ls "$WORK_DIR/apk/lib/" | sort | tr '\n' ' ')
    info "Architectures present: $ARCHS"

    VALID_ARCHS="arm64-v8a armeabi-v7a x86 x86_64"
    for arch_dir in "$WORK_DIR/apk/lib/"*/; do
        arch=$(basename "$arch_dir")
        if ! echo "$VALID_ARCHS" | grep -qw "$arch"; then
            fail "Unknown architecture directory: $arch"
        fi
    done

    # Check for expected Tauri .so file
    for arch_dir in "$WORK_DIR/apk/lib/"*/; do
        arch=$(basename "$arch_dir")
        if [[ -f "$arch_dir/libapp.so" ]]; then
            SO_SIZE=$(stat -c%s "$arch_dir/libapp.so" 2>/dev/null || stat -f%z "$arch_dir/libapp.so" 2>/dev/null)
            info "lib/$arch/libapp.so — $(numfmt --to=iec $SO_SIZE 2>/dev/null || echo "${SO_SIZE} bytes")"
        else
            warn "lib/$arch/libapp.so not found (expected for Tauri)"
        fi
    done
    pass "Native library directory structure looks valid"
else
    fail "No lib/ directory — APK has no native libraries"
fi

# ============================================================================
# CHECK 2: AndroidManifest Permissions & Components
# ============================================================================
header "2. AndroidManifest Permissions & Components"

# Expected permissions from source (main manifest + mobile-bridge)
EXPECTED_PERMISSIONS=(
    "android.permission.INTERNET"
    "android.permission.ACCESS_NETWORK_STATE"
    "android.permission.RECORD_AUDIO"
    "android.permission.ACCESS_WIFI_STATE"
)

# Try to decode manifest
MANIFEST_DECODED=false

if command -v aapt2 &>/dev/null; then
    aapt2 dump xmltree "$APK_PATH" --file AndroidManifest.xml > "$WORK_DIR/manifest_dump.txt" 2>/dev/null && MANIFEST_DECODED=true
elif command -v aapt &>/dev/null; then
    aapt dump xmltree "$APK_PATH" AndroidManifest.xml > "$WORK_DIR/manifest_dump.txt" 2>/dev/null && MANIFEST_DECODED=true
fi

# Fallback: use Python to parse binary XML if available
if [[ "$MANIFEST_DECODED" == "false" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import sys, struct, xml.etree.ElementTree as ET

# Try using androguard if available
try:
    from androguard.core.apk import APK
    a = APK('$APK_PATH')
    perms = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    providers = a.get_providers()
    print('PERMISSIONS:')
    for p in perms: print(f'  {p}')
    print('ACTIVITIES:')
    for a in activities: print(f'  {a}')
    print('SERVICES:')
    for s in services: print(f'  {s}')
    print('RECEIVERS:')
    for r in receivers: print(f'  {r}')
    print('PROVIDERS:')
    for p in providers: print(f'  {p}')
except ImportError:
    # Fallback: just search for permission strings in binary manifest
    with open('$WORK_DIR/apk/AndroidManifest.xml', 'rb') as f:
        data = f.read()
    # Extract UTF-16 strings that look like permissions
    import re
    strings = re.findall(b'android\\.permission\\.[A-Z_]+', data)
    print('PERMISSIONS (binary scan):')
    for s in set(strings):
        print(f'  {s.decode()}')
" > "$WORK_DIR/manifest_dump.txt" 2>/dev/null && MANIFEST_DECODED=true
fi

if [[ "$MANIFEST_DECODED" == "true" ]]; then
    # Extract permissions from dump
    APK_PERMS=$(grep -oP 'android\.permission\.[A-Z_]+' "$WORK_DIR/manifest_dump.txt" | sort -u)

    info "Permissions found in APK:"
    while IFS= read -r perm; do
        [[ -z "$perm" ]] && continue
        EXPECTED=false
        for ep in "${EXPECTED_PERMISSIONS[@]}"; do
            if [[ "$perm" == "$ep" ]]; then
                EXPECTED=true
                break
            fi
        done
        if [[ "$EXPECTED" == "true" ]]; then
            echo -e "    ${GREEN}✓${NC} $perm (expected)"
        else
            echo -e "    ${RED}✗${NC} $perm (UNEXPECTED)"
            ((FAIL++))
        fi
    done <<< "$APK_PERMS"

    # Check if any expected permissions are missing
    for ep in "${EXPECTED_PERMISSIONS[@]}"; do
        if ! echo "$APK_PERMS" | grep -q "$ep"; then
            warn "Expected permission missing: $ep"
        fi
    done

    # Check for extra components (services, receivers) that could be injected
    if grep -qi "service\|receiver" "$WORK_DIR/manifest_dump.txt" 2>/dev/null; then
        SERVICES=$(grep -i "service" "$WORK_DIR/manifest_dump.txt" | head -20)
        if [[ -n "$SERVICES" ]]; then
            info "Services/receivers found in manifest (review manually):"
            echo "$SERVICES" | head -10 | sed 's/^/    /'
        fi
    fi
else
    warn "Could not decode AndroidManifest.xml (install aapt2, androguard, or Android SDK)"
    info "Falling back to binary string scan..."

    # Basic binary string extraction for permissions
    strings "$WORK_DIR/apk/AndroidManifest.xml" 2>/dev/null | grep -oP 'android\.permission\.[A-Z_]+' | sort -u > "$WORK_DIR/binary_perms.txt" || true
    if [[ -s "$WORK_DIR/binary_perms.txt" ]]; then
        info "Permissions found via binary scan:"
        while IFS= read -r perm; do
            EXPECTED=false
            for ep in "${EXPECTED_PERMISSIONS[@]}"; do
                if [[ "$perm" == "$ep" ]]; then
                    EXPECTED=true
                    break
                fi
            done
            if [[ "$EXPECTED" == "true" ]]; then
                echo -e "    ${GREEN}✓${NC} $perm (expected)"
            else
                echo -e "    ${RED}✗${NC} $perm (UNEXPECTED)"
                ((FAIL++))
            fi
        done < "$WORK_DIR/binary_perms.txt"
    else
        warn "Could not extract permissions from binary manifest"
    fi
fi

# ============================================================================
# CHECK 3: Native Library Inspection
# ============================================================================
header "3. Native Library Inspection"

if command -v readelf &>/dev/null; then
    for arch_dir in "$WORK_DIR/apk/lib/"*/; do
        [[ ! -d "$arch_dir" ]] && continue
        arch=$(basename "$arch_dir")
        info "Inspecting $arch libraries:"

        # List all .so files
        SO_FILES=$(find "$arch_dir" -name "*.so" | sort)
        while IFS= read -r so_file; do
            [[ -z "$so_file" ]] && continue
            so_name=$(basename "$so_file")
            so_size=$(stat -c%s "$so_file" 2>/dev/null || stat -f%z "$so_file" 2>/dev/null)
            echo -e "    $so_name ($(numfmt --to=iec $so_size 2>/dev/null || echo "${so_size}B"))"

            # Check NEEDED (shared library dependencies)
            NEEDED=$(readelf -d "$so_file" 2>/dev/null | grep NEEDED | awk '{print $5}' | tr -d '[]')
            if [[ -n "$NEEDED" ]]; then
                # Flag suspicious dependencies
                while IFS= read -r dep; do
                    case "$dep" in
                        libc.so|libm.so|libdl.so|liblog.so|libandroid.so|libGLESv2.so|libEGL.so|libnativewindow.so|libOpenSLES.so|libz.so|libstdc++.so|libc++_shared.so)
                            ;; # expected Android/system libs
                        *)
                            if [[ "$dep" == lib*.so ]]; then
                                info "  NEEDED: $dep"
                            else
                                warn "  Unusual dependency: $dep"
                            fi
                            ;;
                    esac
                done <<< "$NEEDED"
            fi
        done <<< "$SO_FILES"
    done
    pass "Native library inspection complete"
else
    warn "readelf not available — skipping native library inspection"
    info "Install binutils to enable this check"
fi

# ============================================================================
# CHECK 4: DEX Code Verification
# ============================================================================
header "4. DEX Code Verification"

# Expected Java/Kotlin packages for a Tauri app
EXPECTED_PACKAGES=(
    "com/devgriffin/whispercode"
    "app/tauri"
    "androidx/"
    "com/google/android/material"
    "kotlin/"
    "kotlinx/"
    "ai/opencode/mobilebridge"
)

# Suspicious packages that indicate injected code
SUSPICIOUS_PACKAGES=(
    "com/facebook"
    "com/google/firebase/analytics"
    "com/google/firebase/crashlytics"
    "com/google/android/gms/ads"
    "com/appsflyer"
    "com/adjust"
    "com/amplitude"
    "com/mixpanel"
    "com/segment"
    "io/sentry"
    "com/bugsnag"
    "com/crashlytics"
    "com/flurry"
    "com/umeng"
    "com/bytedance"
    "com/tencent"
)

DEX_CHECKED=false

# Try baksmali first (most detailed)
if command -v baksmali &>/dev/null; then
    for dex in "$WORK_DIR/apk/"classes*.dex; do
        [[ ! -f "$dex" ]] && continue
        baksmali disassemble "$dex" -o "$WORK_DIR/smali_$(basename "$dex" .dex)" 2>/dev/null || true
    done

    if [[ -d "$WORK_DIR/smali_classes" ]]; then
        # Get all top-level packages
        PACKAGES=$(find "$WORK_DIR/smali_classes" -name "*.smali" | sed "s|$WORK_DIR/smali_classes/||" | cut -d/ -f1-3 | sort -u)
        DEX_CHECKED=true
    fi
fi

# Fallback: use dexdump
if [[ "$DEX_CHECKED" == "false" ]] && command -v dexdump &>/dev/null; then
    for dex in "$WORK_DIR/apk/"classes*.dex; do
        [[ ! -f "$dex" ]] && continue
        dexdump -l plain "$dex" 2>/dev/null | grep "Class descriptor" | sed "s/.*'L//" | sed "s/;.*//" | cut -d/ -f1-3 | sort -u >> "$WORK_DIR/dex_classes.txt"
    done
    PACKAGES=$(cat "$WORK_DIR/dex_classes.txt" 2>/dev/null | sort -u)
    DEX_CHECKED=true
fi

# Fallback: basic strings extraction from DEX
if [[ "$DEX_CHECKED" == "false" ]]; then
    for dex in "$WORK_DIR/apk/"classes*.dex; do
        [[ ! -f "$dex" ]] && continue
        # Extract class-like strings from DEX
        strings "$dex" 2>/dev/null | grep -oP 'L[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*){1,}' | sed 's/^L//' | cut -d/ -f1-3 | sort -u >> "$WORK_DIR/dex_strings.txt"
    done
    if [[ -s "$WORK_DIR/dex_strings.txt" ]]; then
        PACKAGES=$(sort -u "$WORK_DIR/dex_strings.txt")
        DEX_CHECKED=true
        info "Using string-based extraction (install baksmali or dexdump for more accurate results)"
    fi
fi

if [[ "$DEX_CHECKED" == "true" && -n "${PACKAGES:-}" ]]; then
    # Check for suspicious packages
    FOUND_SUSPICIOUS=""
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        for susp in "${SUSPICIOUS_PACKAGES[@]}"; do
            susp_path="${susp}"
            if [[ "$pkg" == "$susp_path"* ]]; then
                FOUND_SUSPICIOUS="$FOUND_SUSPICIOUS\n    $pkg"
            fi
        done
    done <<< "$PACKAGES"

    if [[ -z "$FOUND_SUSPICIOUS" ]]; then
        pass "No suspicious packages (ad SDKs, trackers) found in DEX"
    else
        fail "Suspicious packages found in DEX:$FOUND_SUSPICIOUS"
    fi

    # Count total unique packages
    PKG_COUNT=$(echo "$PACKAGES" | wc -l)
    info "Total unique package prefixes in DEX: $PKG_COUNT"

    # Show non-standard packages for review
    info "Non-standard packages (review manually):"
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        IS_EXPECTED=false
        for ep in "${EXPECTED_PACKAGES[@]}"; do
            if [[ "$pkg" == "$ep"* ]]; then
                IS_EXPECTED=true
                break
            fi
        done
        if [[ "$IS_EXPECTED" == "false" ]]; then
            echo "    $pkg"
        fi
    done <<< "$PACKAGES"
else
    warn "Could not inspect DEX code (install baksmali, dexdump, or ensure 'strings' is available)"
fi

# Count DEX files
DEX_COUNT=$(find "$WORK_DIR/apk" -maxdepth 1 -name "classes*.dex" | wc -l)
info "DEX files: $DEX_COUNT"
if [[ "$DEX_COUNT" -gt 3 ]]; then
    warn "More than 3 DEX files — unusual for a Tauri app (possible multidex injection)"
fi

# ============================================================================
# CHECK 5: Frontend Assets Comparison
# ============================================================================
header "5. Frontend Assets"

if [[ -d "$WORK_DIR/apk/assets" ]]; then
    ASSET_COUNT=$(find "$WORK_DIR/apk/assets" -type f | wc -l)
    ASSET_SIZE=$(du -sh "$WORK_DIR/apk/assets" 2>/dev/null | cut -f1)
    info "Assets directory: $ASSET_COUNT files, $ASSET_SIZE"

    # List asset file types
    info "Asset file types:"
    find "$WORK_DIR/apk/assets" -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'

    if [[ "$BUILD_FRONTEND" == "true" ]]; then
        info "Building frontend from source for comparison..."
        FRONTEND_DIR="$REPO_ROOT/packages/android"

        if [[ -f "$FRONTEND_DIR/package.json" ]]; then
            (cd "$REPO_ROOT" && bun install --frozen-lockfile 2>/dev/null || bun install) >/dev/null 2>&1
            (cd "$FRONTEND_DIR" && bun run build) >/dev/null 2>&1

            DIST_DIR="$FRONTEND_DIR/dist"
            if [[ -d "$DIST_DIR" ]]; then
                info "Comparing built frontend with APK assets..."
                # The assets are typically under assets/ in the APK
                # Tauri puts them in assets/__tauri/ or similar
                DIFF_OUTPUT=$(diff -rq "$DIST_DIR/" "$WORK_DIR/apk/assets/" 2>&1 || true)
                if [[ -z "$DIFF_OUTPUT" ]]; then
                    pass "Frontend assets match source build exactly"
                else
                    DIFF_LINES=$(echo "$DIFF_OUTPUT" | wc -l)
                    if [[ "$DIFF_LINES" -lt 5 ]]; then
                        warn "Minor differences in frontend assets ($DIFF_LINES diffs):"
                        echo "$DIFF_OUTPUT" | sed 's/^/    /'
                    else
                        fail "Frontend assets differ from source build ($DIFF_LINES diffs)"
                        echo "$DIFF_OUTPUT" | head -10 | sed 's/^/    /'
                        echo "    ... (showing first 10)"
                    fi
                fi
            else
                warn "Frontend build produced no dist/ directory"
            fi
        else
            warn "Cannot build frontend — package.json not found at $FRONTEND_DIR"
        fi
    else
        info "Skipping frontend build comparison (use --build-frontend to enable)"
    fi

    # Check for suspicious files in assets
    SUSPICIOUS_ASSETS=""
    while IFS= read -r f; do
        fname=$(basename "$f")
        case "$fname" in
            *.apk|*.dex|*.so|*.jar)
                SUSPICIOUS_ASSETS="$SUSPICIOUS_ASSETS\n    $f"
                ;;
        esac
    done < <(find "$WORK_DIR/apk/assets" -type f)

    if [[ -z "$SUSPICIOUS_ASSETS" ]]; then
        pass "No suspicious files in assets (no embedded APKs, DEX, SO, or JARs)"
    else
        fail "Suspicious files in assets:$SUSPICIOUS_ASSETS"
    fi
else
    warn "No assets/ directory in APK"
fi

# ============================================================================
# CHECK 6: Signing Certificate
# ============================================================================
header "6. Signing Certificate"

CERT_CHECKED=false

if command -v apksigner &>/dev/null; then
    info "APK signature verification:"
    VERIFY_OUTPUT=$(apksigner verify --print-certs "$APK_PATH" 2>&1) || true
    if [[ -n "$VERIFY_OUTPUT" ]]; then
        echo "$VERIFY_OUTPUT" | sed 's/^/    /'
        CERT_CHECKED=true

        # Extract signer DN for reporting
        SIGNER_DN=$(echo "$VERIFY_OUTPUT" | grep "DN:" | head -1)
        if [[ -n "$SIGNER_DN" ]]; then
            info "Primary signer: $SIGNER_DN"
        fi
    fi
fi

if [[ "$CERT_CHECKED" == "false" ]] && command -v keytool &>/dev/null; then
    # Extract cert from META-INF
    CERT_FILE=$(find "$WORK_DIR/apk/META-INF" -name "*.RSA" -o -name "*.DSA" -o -name "*.EC" 2>/dev/null | head -1)
    if [[ -n "$CERT_FILE" ]]; then
        info "Certificate details:"
        keytool -printcert -file "$CERT_FILE" 2>/dev/null | head -20 | sed 's/^/    /'
        CERT_CHECKED=true
    fi
fi

if [[ "$CERT_CHECKED" == "false" ]]; then
    # At minimum, check what signing files exist
    info "META-INF contents:"
    ls "$WORK_DIR/apk/META-INF/" 2>/dev/null | sed 's/^/    /'

    SIGNING_FILES=$(find "$WORK_DIR/apk/META-INF" -name "*.RSA" -o -name "*.DSA" -o -name "*.EC" -o -name "*.SF" 2>/dev/null | wc -l)
    if [[ "$SIGNING_FILES" -gt 0 ]]; then
        info "Signing files present ($SIGNING_FILES found)"
    else
        warn "No standard signing files found in META-INF/"
    fi
    warn "Install apksigner or keytool for detailed certificate analysis"
fi

# Check for v2/v3 signing (more secure)
if command -v apksigner &>/dev/null; then
    V2_SIGNED=$(apksigner verify -v "$APK_PATH" 2>&1 | grep "v2 scheme" || true)
    if echo "$V2_SIGNED" | grep -q "true"; then
        pass "APK uses v2 signing scheme"
    else
        warn "APK may not use v2 signing scheme (v1 only is less secure)"
    fi
fi

# ============================================================================
# CHECK 7: APK Size Analysis
# ============================================================================
header "7. APK Size Analysis"

APK_SIZE=$(stat -c%s "$APK_PATH" 2>/dev/null || stat -f%z "$APK_PATH" 2>/dev/null)
APK_SIZE_HR=$(numfmt --to=iec "$APK_SIZE" 2>/dev/null || echo "${APK_SIZE} bytes")
info "Total APK size: $APK_SIZE_HR"

# Size breakdown by directory
info "Size breakdown:"
for dir in lib assets res classes.dex META-INF; do
    if [[ -e "$WORK_DIR/apk/$dir" ]]; then
        DIR_SIZE=$(du -sh "$WORK_DIR/apk/$dir" 2>/dev/null | cut -f1)
        echo "    $dir: $DIR_SIZE"
    fi
done

# Flag if APK is suspiciously large (>100MB for a single-arch build)
if [[ "$APK_SIZE" -gt 104857600 ]]; then
    warn "APK is larger than 100MB — unusually large for WhisperCode"
fi

# ============================================================================
# SUMMARY
# ============================================================================
header "Verification Summary"

echo ""
echo -e "  ${GREEN}Passed:  $PASS${NC}"
echo -e "  ${YELLOW}Warnings: $WARN${NC}"
echo -e "  ${RED}Failed:  $FAIL${NC}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}APK verification found $FAIL failure(s). Review the output above.${NC}"
    echo ""
    echo "Failures indicate the APK may contain injected or unexpected content."
    echo "Consider building the APK yourself from source and comparing."
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    echo -e "${YELLOW}APK verification completed with $WARN warning(s). Review the output above.${NC}"
    echo ""
    echo "Warnings may be due to missing analysis tools. Install the suggested tools"
    echo "for more thorough verification."
    exit 0
else
    echo -e "${GREEN}All checks passed. No anomalies detected.${NC}"
    exit 0
fi
