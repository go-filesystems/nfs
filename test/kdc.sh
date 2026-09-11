#!/bin/sh
# Builds a throwaway MIT Kerberos realm on loopback, unprivileged, and prints
# the environment the tests need.
#
# A copy of go-authn/krb5's test/kdc.sh. It is duplicated rather than shared
# because a shell fixture is not importable: the alternative was a Go module
# whose only export is a path to a script, which buys nothing.
#
# Nothing here touches the machine's own Kerberos configuration.
#
#   eval "$(test/kdc.sh /tmp/krbtest)"
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
run() { if [ -z "$RUN" ]; then "$@"; else $RUN "$@"; fi; }

# pkgx fetches a package the first time it is USED, so the bottle has to be
# materialised before anything can be found inside it. Without this the search
# below finds nothing, db_module_dir is written empty, and every later command
# fails with "Improper format of Kerberos configuration file" — which names
# the file and not the empty value in it.
run krb5-config --version >/dev/null 2>&1 || true

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
    echo "        kdc = 127.0.0.1:$PORT"
    echo "        database_name = $DIR/db/principal"
    echo "        key_stash_file = $DIR/db/stash"
    echo "        acl_file = $DIR/kadm5.acl"
    echo "    }"
    echo "[domain_realm]"
    echo "    localhost = $REALM"
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
    echo "    kdc_listen = 127.0.0.1:$PORT"
    # krb5kdc logs to syslog by default, and then exits 1 without a word when
    # anything goes wrong. A FILE destination is how you find out why.
    echo "[logging]"
    echo "    kdc = FILE:$DIR/kdc.log"
    echo "    default = FILE:$DIR/kdc.log"
} > "$DIR/krb5.conf"
: > "$DIR/kadm5.acl"
export KRB5_CONFIG="$DIR/krb5.conf"

run kdb5_util create -s -r "$REALM" -P masterkey >/dev/null
ka() { run kadmin.local -r "$REALM" -q "$1" >/dev/null 2>&1; }
ka "addprinc -pw $USER_PW alice@$REALM"
for host in localhost "$SHORT" "$FQDN"; do
    ka "addprinc -randkey $SERVICE/$host@$REALM"
    ka "ktadd -k $DIR/service.keytab $SERVICE/$host@$REALM"
done

# -n keeps it in the foreground; without it krb5kdc forks and the pid file it
# writes is the only handle left. -p sets the UDP port ONLY: without
# kdc_tcp_ports above the TCP socket falls back to the privileged 88 and the
# failure reads "Address already in use".
run krb5kdc -n -r "$REALM" >/dev/null 2>&1 &
echo $! > "$DIR/kdc.pid"
sleep 2

export KRB5CCNAME="FILE:$DIR/ccache"
echo "$USER_PW" | run kinit "alice@$REALM" >/dev/null 2>&1

cat <<EOF
export KRB5_CONFIG=$DIR/krb5.conf
export KRB5CCNAME=FILE:$DIR/ccache
export KRB5_TEST_KEYTAB=$DIR/service.keytab
export KRB5_TEST_SERVICE=$SERVICE
export KRB5_TEST_DIR=$DIR
EOF
