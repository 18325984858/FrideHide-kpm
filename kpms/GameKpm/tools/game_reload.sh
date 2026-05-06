#!/system/bin/sh
#
# GameKpm 一键热重载 + 联动 inject-hide
#
# KernelPatch 没有把 module_control0 导出给 KPM, 所以 GameKpm 不能在
# 内核态直接调 inject-hide; 这里在 shell 编排层串行 ctl0:
#
#   1. unload 旧 game-kpm (容错)
#   2. load svc.kpm (inject-hide) 如未加载
#   3. load game-kpm.kpm
#   4. 通过 svc.kpm 注册目标包名 / frida 关键词 / SO 关键词 / 启用文件级隐藏
#   5. 启用 GameKpm 自身的反检测开关
#   6. 输出 status
#
# 用法 (设备 root shell)：
#   sh /data/local/tmp/game_reload.sh                 # 默认 dfm
#   sh /data/local/tmp/game_reload.sh pubgmhd
#   sh /data/local/tmp/game_reload.sh dfm /sdcard/Download/game-kpm.kpm
#

set -u

# ─── 路径与超级钥匙 ───
KP=${KP:-/data/data/me.bmax.apatch/patch/kpatch}

# Superkey 解析顺序（与 game/app 的 kp_ctl.cpp::detect_superkey_from_files 对齐）：
#   1. 环境变量 $SK
#   2. /data/local/tmp/.kp_key
#   3. /sdcard/kpkey.txt
#   4. /data/adb/kp/superkey
#   5. /data/adb/ap/superkey
#   6. /data/adb/.superkey
#   7. 兜底字面量 "songfukun183"（仅本机历史值，公开发布时应删）
if [ -z "${SK:-}" ]; then
    for f in /data/local/tmp/.kp_key /sdcard/kpkey.txt /data/adb/kp/superkey \
             /data/adb/ap/superkey /data/adb/.superkey; do
        if [ -f "$f" ]; then
            v=$(cat "$f" 2>/dev/null | tr -d ' \r\n')
            if [ -n "$v" ]; then SK="$v"; break; fi
        fi
    done
fi
SK=${SK:-songfukun183}
echo "[*] using superkey: ${SK:0:3}***${SK: -3} (len=${#SK})"

PRESET="${1:-dfm}"
KPM_PATH="${2:-/sdcard/Download/game-kpm.kpm}"
SVC_PATH="${SVC_PATH:-/sdcard/Download/svc.kpm}"

case "$PRESET" in
    dfm)
        PKG="com.tencent.tmgp.dfm" ;;
    pubgmhd)
        PKG="com.tencent.tmgp.pubgmhd" ;;
    *)
        echo "[!] preset must be 'dfm' or 'pubgmhd'"
        exit 1 ;;
esac

echo "[*] preset=$PRESET pkg=$PKG kpm=$KPM_PATH"

ctl_svc()  { $KP $SK kpm ctl0 kpm-svc   "$1" 2>&1; }
ctl_game() { $KP $SK kpm ctl0 game-kpm  "$1" 2>&1; }

# 1. 卸载旧 game-kpm（容错）
$KP $SK kpm unload game-kpm >/dev/null 2>&1 || true
echo "[*] previous game-kpm unloaded (if any)"

# 2. 确保 svc.kpm 已加载
if ! $KP $SK kpm list 2>&1 | grep -q '^kpm-svc$'; then
    echo "[*] loading $SVC_PATH"
    $KP $SK kpm load "$SVC_PATH" 2>&1
fi

# 3. 加载 game-kpm
$KP $SK kpm load "$KPM_PATH" 2>&1
echo "[*] game-kpm loaded"

# 4. inject-hide 端：注册包名、frida 关键词、SO 关键词、启用文件级隐藏
ctl_svc "add_hide_pkg:$PKG"
ctl_svc "add_hide_comm:gum-js-loop"
ctl_svc "add_hide_comm:gmain"
ctl_svc "add_hide_comm:gdbus"
ctl_svc "add_hide_comm:linjector"
ctl_svc "add_hide_comm:pool-frida"
ctl_svc "add_hide_comm:GumJS"
ctl_svc "add_hide_so:frida"
ctl_svc "add_hide_so:gum"
# 注意：刻意不加 libdobbyproject / libdobby —— 这两个关键词会在 enable_file_hide
# 时拦下 dobbyproject 自家 APK 加载（APK 路径里就包含 'libdobbyproject' 子串），
# 而 dobbyproject 自己启动时还没机会调 setSuperkey → 不在 trusted 列表 → 被全局拦。
# inject-hide 默认加载时已经自动种子 libdobby/dobby 关键词到 hide_so，且通过
# add_hide_pkg:com.example.dobbyproject 自动豁免 dobbyproject 自身的 caller，
# 所以这里不需要重复添加。
ctl_svc "enable_file_hide"
echo "[*] inject-hide configured for $PKG"

# 5. game-kpm 端：启用反检测开关 + 注册 comm 前缀
ctl_game "enable_log"
ctl_game "preset_$PRESET"   # 同样会调 delegate_*（失败也无所谓，已在 shell 完成）
echo "[*] game-kpm switches enabled"

# 6. 启动游戏 + 等 pid 出现 → 注册 tgid 进 GameKpm
echo "[*] launching $PKG ..."
am force-stop "$PKG" >/dev/null 2>&1 || true
monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
LEADER=
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    sleep 1
    # 找 cmdline 完全匹配 PKG 的领导线程（排除 :gpu / :tdr 等子进程）
    LEADER=$(for p in $(pgrep -f "$PKG" 2>/dev/null); do
                cmd=$(cat /proc/$p/cmdline 2>/dev/null | tr -d '\0')
                [ "$cmd" = "$PKG" ] && echo $p && break
              done | head -1)
    [ -n "$LEADER" ] && break
done
if [ -n "$LEADER" ]; then
    ctl_game "add_target_pid:$LEADER"
    # 同包名子进程（PKG:xxx）一并注册
    for p in $(pgrep -f "$PKG" 2>/dev/null); do
        [ "$p" = "$LEADER" ] && continue
        ctl_game "add_target_pid:$p"
    done
    echo "[*] tgid registered: leader=$LEADER + $(pgrep -f $PKG | wc -l) total processes"
else
    echo "[!] $PKG did not launch within 15s — tgid not registered"
fi

# 7. status
echo
ctl_game "status"
