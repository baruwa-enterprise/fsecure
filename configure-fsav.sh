#!/usr/bin/env bash
# set -e
RETRY_MAX=10
sed -i -e 's/^odsFileScanInsideMIME\s\+[0-9]/odsFileScanInsideMIME 1/' \
    -e 's/^odsFilePrimaryActionOnInfection\s\+[0-9]/odsFilePrimaryActionOnInfection 1/' \
    -e 's/^odsFileSecondaryActionOnInfection\s\+[0-9]/odsFileSecondaryActionOnInfection 2/' \
    -e 's/^odsAskQuestions\s\+[0-9]/odsAskQuestions 0/' \
    -e 's/^odsFollowSymlinks\s\+[0-9]/odsFollowSymlinks 1/' \
    -e 's/^daemonLogfileEnabled\s\+[0-9]/daemonLogfileEnabled 1/' \
    -e 's/^daemonSocketMode\s\+[0-9]\+/daemonSocketMode 0666/' \
    -e 's/^socketpathGroup\s\+\S\+/socketpathGroup Debian-exim/' /etc/opt/f-secure/fssp/fssp.conf
cp -v /opt/f-secure/fssp/etc/fsavd /etc/init.d/
chmod +x /etc/init.d/fsavd
/etc/init.d/fsavd start
for i in $(seq 1 ${RETRY_MAX}); do
    echo "Running dbupdate => ${i}"
    /opt/f-secure/fssp/bin/dbupdate
    EXIT_CODE=$?
    [ "$EXIT_CODE" == "0" ] && break
    sleep $((5 * $i))
    /opt/f-secure/fssp/bin/fsav --version
done
/etc/init.d/fsavd status
ls -la /tmp
exit $EXIT_CODE
