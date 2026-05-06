#!/usr/bin/env bash
#
# auto_test.sh — GameKpm 自动化回归
#
# 流程:
#   1. 在 host 重新 build → adb push
#   2. 通过 root shell 重新 load svc.kpm + game-kpm.kpm
#   3. 启动目标游戏 (默认 dfm)
#   4. 持续 N 秒采样:
#      - logcat 关键字 (FATAL / SIGNAL / TerSafe / TPRT / kill / abort)
#      - dmesg 关键字 (GAMEKPM / [SFK] / SIGKILL)
#      - ps 看进程是否还活着
#   5. 输出生还指标 + 触发的检测路径
#
# 用法:
#   ./auto_test.sh                  # 默认 dfm，采样 30s
#   ./auto_test.sh dfm 60
#   ./auto_test.sh pubgmhd 30
#

set -u

PRESET="${1:-dfm}"
SAMPLE_SECS="${2:-30}"

case "$PRESET" in
    dfm)      PKG="com.tencent.tmgp.dfm";       ACT="$PKG/com.tencent.tmgp.dfm.SGameActivity" ;;
    pubgmhd)  PKG="com.tencent.tmgp.pubgmhd";   ACT="" ;;
    *)        echo "preset must be dfm|pubgmhd"; exit 1 ;;
esac

KP=/data/data/me.bmax.apatch/patch/kpatch
SK=songfukun183

H_DIR="$(cd "$(dirname "$0")/.." && pwd)"          # GameKpm/
LOG_DIR="$H_DIR/test_runs"
mkdir -p "$LOG_DIR"
TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$LOG_DIR/run_${PRESET}_${TS}"
mkdir -p "$RUN_DIR"

echo "[*] preset=$PRESET pkg=$PKG samples=${SAMPLE_SECS}s logs=$RUN_DIR"

# ─── 1. build + push ───
echo "[*] building..."
( cd "$H_DIR" && make ) 2>&1 | tee "$RUN_DIR/build.log" | tail -5
test -f "$H_DIR/game-kpm.kpm" || { echo "[!] build failed"; exit 1; }

adb push "$H_DIR/game-kpm.kpm"           /sdcard/Download/game-kpm.kpm   >/dev/null
adb push "$H_DIR/tools/game_reload.sh"   /data/local/tmp/game_reload.sh  >/dev/null
adb shell chmod +x /data/local/tmp/game_reload.sh
echo "[*] pushed."

# ─── 2. force-stop 游戏 → 卸载旧 KPM → 重新装 ───
adb shell "su -c 'am force-stop $PKG'"  >/dev/null 2>&1 || true
adb shell "su -c '$KP $SK kpm unload game-kpm; $KP $SK kpm unload kpm-svc' " >/dev/null 2>&1 || true
sleep 1

# 清理旧 dmesg 头水位（用 -c 在 KP 设备上不一定可用，改成记录基线时间戳）
BASE_TS=$(adb shell "su -c 'cat /proc/uptime'" | awk '{print $1}')
echo "[*] kernel uptime base = $BASE_TS"

adb shell "su -c 'sh /data/local/tmp/game_reload.sh $PRESET'" \
    > "$RUN_DIR/reload.log" 2>&1
tail -20 "$RUN_DIR/reload.log"

# ─── 3. 游戏已被 game_reload.sh 启动并注册 tgid，直接采样 ───
adb logcat -c >/dev/null 2>&1 || true
sleep 2

# 后台采集 logcat（用 timeout 限定生命周期，避免悬挂阻塞 stdout 管道）
( timeout $((SAMPLE_SECS + 5)) adb logcat -v time \
    | egrep -i 'FATAL|tombstone|SIGNAL|TerSafe|TPRT|tss|tprt|libtersafe|libtprt|abort|kill|GAMEKPM' \
    > "$RUN_DIR/logcat.log" ) &
LOGCAT_PID=$!

# ─── 4. 采样 ───
ALIVE_LOG="$RUN_DIR/alive.csv"
echo "ts,pid,cmd" > "$ALIVE_LOG"

for i in $(seq 1 "$SAMPLE_SECS"); do
    LINE=$(adb shell "su -c 'pgrep -af $PKG'" 2>/dev/null | head -1 | tr -d '\r')
    if [ -n "$LINE" ]; then
        PID=$(echo "$LINE" | awk '{print $1}')
        echo "$i,$PID,$LINE" >> "$ALIVE_LOG"
    else
        echo "$i,," >> "$ALIVE_LOG"
    fi
    sleep 1
done

kill "$LOGCAT_PID" 2>/dev/null || true

# 拉 dmesg 自基线起
adb shell "su -c 'dmesg | tail -400'" > "$RUN_DIR/dmesg.log" 2>&1

# ─── 5. 总结 ───
echo
echo "=== Summary ==="
ALIVE_COUNT=$(awk -F, 'NR>1 && $2!="" {c++} END{print c+0}' "$ALIVE_LOG")
DEAD_COUNT=$((SAMPLE_SECS - ALIVE_COUNT))
echo "alive samples : $ALIVE_COUNT / $SAMPLE_SECS"
echo "dead  samples : $DEAD_COUNT"

if [ "$ALIVE_COUNT" -eq "$SAMPLE_SECS" ]; then
    echo "[✓] 进程全程存活"
else
    echo "[✗] 进程在 $((ALIVE_COUNT))s 后退出 — 看下面线索"
    echo
    echo "--- last 30 logcat ---"
    tail -30 "$RUN_DIR/logcat.log"
    echo
    echo "--- last 20 GAMEKPM lines from dmesg ---"
    grep -E 'GAMEKPM|\[SFK\]|kill|SIGKILL' "$RUN_DIR/dmesg.log" | tail -20
fi

echo
echo "[*] full logs in: $RUN_DIR"
