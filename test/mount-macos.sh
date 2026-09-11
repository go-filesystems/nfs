#!/bin/sh
# Mounts a sec=krb5 export from this server with macOS's own NFS client, as a
# foreign judge for RFC 2203.
#
# ⚠ THIS SCRIPT NEEDS A HUMAN. It is not run by `go test`, and it should not
# be: it changes two things outside any repository and both need a decision.
#
#   1. /etc/krb5.conf. macOS's NFS client does its Kerberos in gssd, a
#      per-user launchd agent that reads the SYSTEM configuration. KRB5_CONFIG
#      reaches the tests and does not reach gssd, so the test realm has to be
#      visible machine-wide for the duration.
#
#   2. mount(8), which is root's.
#
# Both are undone by --clean. Read what it does before running it.
#
#   test/kdc.sh /tmp/krbtest > /tmp/krbtest.env && . /tmp/krbtest.env
#
# Then start a server that exports something and has been given a
# github.com/go-filesystems/nfs/rpcgss authenticator — go-fileshare is the
# one built for this; this module deliberately ships no such command, because
# it would drag a filesystem driver into the dependencies of everything that
# imports nfs.
#
#   sudo test/mount-macos.sh /tmp/krbtest
#   test/mount-macos.sh --clean
set -eu

MNT=${MOUNTPOINT:-/tmp/nfs-krb5}
PORT=${NFS_PORT:-12049}

if [ "${1:-}" = "--clean" ]; then
    umount "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
    if [ -f /etc/krb5.conf.before-nfs-judge ]; then
        sudo mv /etc/krb5.conf.before-nfs-judge /etc/krb5.conf
        echo "restored the previous /etc/krb5.conf"
    else
        sudo rm -f /etc/krb5.conf
        echo "removed /etc/krb5.conf (there was none before)"
    fi
    exit 0
fi

DIR=${1:?usage: mount-macos.sh <realm directory from kdc.sh> | --clean}
[ -f "$DIR/krb5.conf" ] || { echo "no krb5.conf in $DIR" >&2; exit 1; }

# Keep whatever was there. A machine that already has a realm configured must
# get it back, and "there was none" is a different fact from "there was one".
if [ -f /etc/krb5.conf ] && [ ! -f /etc/krb5.conf.before-nfs-judge ]; then
    sudo cp /etc/krb5.conf /etc/krb5.conf.before-nfs-judge
fi
sudo cp "$DIR/krb5.conf" /etc/krb5.conf

# The ticket must be in the SYSTEM cache, which is what gssd reads — not in
# the FILE: cache the tests use. Heimdal's kinit is the one that fills it.
/usr/bin/kinit alice@FLEET.TEST

mkdir -p "$MNT"
# nfsvers=3 because that is what this server speaks; port and mountport are
# given explicitly because nothing registers with a portmapper here.
sudo mount -t nfs -o vers=3,sec=krb5,port=$PORT,mountport=$PORT,noresvport,soft,timeo=30 \
    localhost:/ "$MNT"
echo "mounted at $MNT — ls it, then run: test/mount-macos.sh --clean"
