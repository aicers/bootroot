# shellcheck shell=bash
# Free-host-port allocation for the Docker E2E harness.
#
# A harness that has to stand its stack up beside another one cannot take
# the compose file's published defaults: two runs on one host cannot both
# publish `127.0.0.1:8200`.  It picks its four ports instead, and hands
# them to `infra install` as flags so the install records them.
#
# The allocation is advisory rather than a reservation — the kernel hands
# back a port that was free at that instant and nothing holds it until
# `infra install` binds it — and that is deliberate.  `infra install`
# binds every published port up front and aborts with `host port <addr>
# is already in use`, so a pick that went stale surfaces there, with the
# port in the message, instead of turning into a second timeout layer
# here.  Neither branch below ever waits on an occupied port.
#
# Callers must define `fail`, which aborts the harness with a message.

# Ports this process has already handed out.
#
# A port the kernel called free stays free until something binds it, and
# nothing does until the install runs — so without this list one run
# could hand the same port to two of its own services and only find out
# at `up`.
PORTS_TAKEN=""

# Interpreter used for the bind-to-port-0 allocation.
#
# Resolved on first use, so a caller that already located one can pin it
# and a caller that has not needs no setup.  An empty value after the
# resolution attempt selects the randomised-probe branch below rather
# than failing: python3 is a convenience here, not a prerequisite.
PYTHON_BIN="${PYTHON_BIN:-}"

# The port `pick_free_port` last handed out.
#
# The result travels through a global rather than stdout because the
# already-handed-out list has to survive the call, and a command
# substitution would keep it inside a subshell.
PICKED_PORT=0

port_is_taken() {
  local port="$1" taken
  for taken in $PORTS_TAKEN; do
    [ "$taken" = "$port" ] && return 0
  done
  return 1
}

# Picks a free host port on 127.0.0.1 into `PICKED_PORT`.
#
# Prefers the bind-to-port-0 allocation `free_port` in
# tests/bootroot_cli.rs uses: the kernel hands back a port that was free
# at that instant.  Without python3 the fallback probes a randomised high
# range instead.
pick_free_port() {
  local attempt port
  [ -n "$PYTHON_BIN" ] || PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
  for attempt in $(seq 1 200); do
    if [ -n "$PYTHON_BIN" ]; then
      port="$("$PYTHON_BIN" -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
    else
      port=$((20000 + RANDOM % 30000))
      if bash -c ": >/dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
        continue
      fi
    fi
    if [ -n "$port" ] && ! port_is_taken "$port"; then
      PORTS_TAKEN="$PORTS_TAKEN $port"
      PICKED_PORT="$port"
      return 0
    fi
  done
  fail "could not allocate a free host port after 200 attempts"
}
