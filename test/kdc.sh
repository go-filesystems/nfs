#!/bin/sh
# Builds a throwaway MIT Kerberos realm on loopback, unprivileged, and writes
# the environment the tests need.
#
# A copy of go-authn/krb5's test/kdc.sh. It is duplicated rather than shared
# because a shell fixture is not importable: the alternative was a Go module
# whose only export is a path to a script, which buys nothing.
#
# Nothing here touches the machine's own Kerberos configuration.
#
#   test/kdc.sh /tmp/krbtest
#   set -a; . /tmp/krbtest/env; set +a
#   go test ./...
#
# It uses the system's MIT binaries when they are installed and falls back to
# pkgx. On a pkgx bottle the compiled-in plugin directory is the BUILDER's
# (/opt/.../+brewing/...), which does not exist on this machine, and the KDC
# then refuses to create its database with a message that blames a missing
# symbol rather than a missing directory. db_module_dir below is what fixes
# that, and it is harmless on a system install.
set -eu

DIR=${1:-${TMPDIR:-/tmp}/krb5-judge}
REALM=${KRB5_TEST_REALM:-FLEET.TEST}
PORT=${KRB5_TEST_PORT:-8888}
# Which address the KDC answers on. Loopback by default, because a test realm
# that listens on the network is a service nobody asked for; set it when the
# client is somewhere else, such as a VM.
LISTEN=${KRB5_TEST_LISTEN:-127.0.0.1}
USER_PW=${KRB5_TEST_PASSWORD:-alicepw}
SERVICE=${KRB5_TEST_SERVICE:-nfs}

if command -v krb5kdc >/dev/null 2>&1; then
    RUN=""
elif command -v pkgx >/dev/null 2>&1; then
    RUN="pkgx +kerberos.org --"
else
    echo "no MIT Kerberos: install krb5-kdc, or pkgx" >&2
    exit 1
fi
# say reports progress on stderr, which is free: stdout is what the caller
# evaluates. Without it a step that stops partway looks identical to one that
# is merely slow, and the only evidence is the job being killed.
say() { echo "kdc.sh: $*" >&2; }

# run invokes an MIT binary. Callers redirect stdin themselves: everything
# here must be non-interactive — pkgx ASKS when it cannot find a command, and
# on a CI runner the answer never comes, so the step hangs until the job is
# killed rather than failing with something to read.
run() { if [ -z "$RUN" ]; then "$@"; else $RUN "$@"; fi; }

# pkgx fetches a package the first time it is USED, so the bottle has to be
# materialised before anything can be found inside it. Without this the search
# below finds nothing, db_module_dir is written empty, and every later command
# fails with "Improper format of Kerberos configuration file" — which names
# the file and not the empty value in it.
say "materialising the Kerberos package"
run klist -V </dev/null >/dev/null 2>&1 || true

# Where the KDB plugin actually is, as opposed to where the binary was told.
PLUGINS=""
for d in "$HOME"/.pkgx/kerberos.org/v*/lib/krb5/plugins/kdb \
         /usr/lib/*/krb5/plugins/kdb /usr/lib/krb5/plugins/kdb; do
    if [ -d "$d" ]; then PLUGINS=$d; fi
done

# The client CANONICALISES the host it is given, so the service principal has
# to exist under the name the client will ask for, not the one we had in mind.
# That name is the machine's name plus the resolver's search domain: asking
# for "localhost" here produced nfs/<host>.<search domain>@REALM, and a realm
# built without it answers "not found in Kerberos database".
SHORT=$(hostname -s 2>/dev/null || hostname)
DOMAIN=$(awk '/^(search|domain)[ \t]/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
FQDN=$(hostname -f 2>/dev/null || hostname)
case "$FQDN" in
    *.*) ;;
    *)   if [ -n "${DOMAIN:-}" ]; then FQDN="$SHORT.$DOMAIN"; fi ;;
esac

rm -rf "$DIR"
mkdir -p "$DIR/db"

{
    echo "[libdefaults]"
    echo "    default_realm = $REALM"
    echo "    dns_lookup_kdc = false"
    echo "    dns_canonicalize_hostname = false"
    echo "    rdns = false"
    echo "[realms]"
    echo "    $REALM = {"
    echo "        kdc = $LISTEN:$PORT"
    echo "        database_name = $DIR/db/principal"
    echo "        key_stash_file = $DIR/db/stash"
    echo "        acl_file = $DIR/kadm5.acl"
    echo "    }"
    echo "[domain_realm]"
    echo "    localhost = $REALM"
    if [ -n "${DOMAIN:-}" ]; then
        echo "    localhost.$DOMAIN = $REALM"
    fi
    echo "    $SHORT = $REALM"
    echo "    $FQDN = $REALM"
    if [ -n "${DOMAIN:-}" ]; then
        echo "    $DOMAIN = $REALM"
        echo "    .$DOMAIN = $REALM"
    fi
    if [ -n "$PLUGINS" ]; then
        echo "[dbmodules]"
        echo "    db_module_dir = $PLUGINS"
    fi
    echo "[kdcdefaults]"
    echo "    kdc_ports = $PORT"
    echo "    kdc_tcp_ports = $PORT"
    echo "    kdc_listen = $LISTEN:$PORT"
    # krb5kdc logs to syslog by default, and then exits 1 without a word when
    # anything goes wrong. A FILE destination is how you find out why.
    echo "[logging]"
    echo "    kdc = FILE:$DIR/kdc.log"
    echo "    default = FILE:$DIR/kdc.log"
} > "$DIR/krb5.conf"
: > "$DIR/kadm5.acl"
export KRB5_CONFIG="$DIR/krb5.conf"

say "creating the database for $REALM"
run kdb5_util create -s -r "$REALM" -P masterkey </dev/null >/dev/null
ka() { run kadmin.local -r "$REALM" -q "$1" </dev/null >/dev/null 2>&1; }
say "adding principals"
ka "addprinc -pw $USER_PW alice@$REALM"
# The names a client may canonicalise to, not the ones we had in mind. A
# resolver with a search domain turns "localhost" into "localhost.<domain>",
# and on a GitHub runner that domain is a per-VM string nobody could have
# guessed: the KDC then answers "Server not found in Kerberos database" for a
# principal whose name appears nowhere in this script.
HOSTS="localhost $SHORT $FQDN"
if [ -n "${DOMAIN:-}" ]; then
    HOSTS="$HOSTS localhost.$DOMAIN"
fi
for host in $HOSTS; do
    ka "addprinc -randkey $SERVICE/$host@$REALM"
    ka "ktadd -k $DIR/service.keytab $SERVICE/$host@$REALM"
done

# -n keeps it in the foreground; without it krb5kdc forks and the pid file it
# writes is the only handle left. -p sets the UDP port ONLY: without
# kdc_tcp_ports above the TCP socket falls back to the privileged 88 and the
# failure reads "Address already in use".
say "starting the KDC on 127.0.0.1:$PORT"
if command -v setsid >/dev/null 2>&1; then
    setsid ${RUN:-} krb5kdc -n -r "$REALM" </dev/null >"$DIR/kdc.out" 2>&1 &
else
    run krb5kdc -n -r "$REALM" </dev/null >"$DIR/kdc.out" 2>&1 &
fi
echo $! > "$DIR/kdc.pid"
sleep 2

export KRB5CCNAME="FILE:$DIR/ccache"
say "asking for a ticket"
if ! echo "$USER_PW" | run kinit "alice@$REALM" >/dev/null 2>&1; then
    say "kinit FAILED; the KDC said:"
    tail -5 "$DIR/kdc.log" "$DIR/kdc.out" >&2 2>/dev/null || true
    exit 1
fi
say "ready"

# The environment goes into a FILE, and nothing is written to stdout.
#
# It used to print the exports for `eval "$(kdc.sh ...)"`, and that hung a CI
# job for nine minutes THROUGH a timeout: a command substitution waits for
# the write end of its pipe to close in every process that holds it, on any
# descriptor. The backgrounded KDC held one, `timeout` killed only the script
# it started, and the step sat there with nothing to read. A file cannot do
# that.
#
# The lines are KEY=value, which is what GITHUB_ENV wants; in a shell use
#
#	set -a; . "$DIR/env"; set +a
cat > "$DIR/env" <<EOF
KRB5_CONFIG=$DIR/krb5.conf
KRB5CCNAME=FILE:$DIR/ccache
KRB5_TEST_KEYTAB=$DIR/service.keytab
KRB5_TEST_SERVICE=$SERVICE
KRB5_TEST_REALM=$REALM
KRB5_TEST_DIR=$DIR
EOF
say "environment written to $DIR/env"
