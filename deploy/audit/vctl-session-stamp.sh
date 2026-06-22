# /etc/profile.d/vctl-session-stamp.sh
# SSH 로그인 셸에서 cert serial→세션 마커 기록. (sourced; 실행권한 불필요)
#
# 왜 PAM 이 아니라 profile.d 인가: sshd ExposeAuthInfo 의 $SSH_USER_AUTH 는 "세션 셸"
# 환경에만 들어가고 pam_exec 세션 훅은 받지 못한다(검증 완료). 로그인 셸에선 존재하므로
# 여기서 cert 를 읽어 serial 을 뽑아 /run/vctl/sessions/<pid>.json 마커를 남기고,
# vctl-watch-sessions 데몬이 이를 audit_session 으로 등록한다.
#
# 마커 디렉터리는 root 소유(0700) → root 로그인(seoul fleet)에서 동작. 비-root 로그인
# 호스트는 watch-sessions 의 journal-tail 방식(후속) 또는 디렉터리 권한 조정 필요.
[ -n "${SSH_USER_AUTH:-}" ] && [ -r "$SSH_USER_AUTH" ] || return 0 2>/dev/null

_vctl_serial=""
_vctl_cl=$(grep -m1 'cert-v01@openssh.com' "$SSH_USER_AUTH" 2>/dev/null)
if [ -n "$_vctl_cl" ]; then
  _vctl_t=$(mktemp)
  printf '%s\n' "$_vctl_cl" | sed 's/^publickey //' > "$_vctl_t"
  _vctl_serial=$(ssh-keygen -L -f "$_vctl_t" 2>/dev/null | awk -F'Serial: ' '/Serial:/{print $2;exit}')
  rm -f "$_vctl_t"
fi
_vctl_lp=$PPID
# started = 로그인 시각(불변). watch-sessions 재시작 시 같은 세션이 같은 키로 upsert 되어
# 중복 등록/“live” 누적을 막는다.
_vctl_st=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p /run/vctl/sessions 2>/dev/null && cat > "/run/vctl/sessions/${_vctl_lp}.json" 2>/dev/null <<EOF
{"serial":"${_vctl_serial}","login":"$(id -un)","rhost":"${SSH_CONNECTION%% *}","leader_pid":${_vctl_lp},"host":"$(hostname)","started":"${_vctl_st}"}
EOF
unset _vctl_serial _vctl_cl _vctl_t _vctl_lp _vctl_st
