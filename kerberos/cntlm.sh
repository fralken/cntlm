#!/bin/zsh

SDIR=$( cd "$( dirname "$0" )" && pwd )
LOG=$SDIR/cntlm.out
CNTLM=cntlm
INTERNAL=cntlm_internal.conf
EXTERNAL=cntlm_external.conf

# send SIGTERM signal twice
pkill $CNTLM
pkill $CNTLM
if [[ "$1" == "start" ]]
then
    scutil --dns | grep "10\." > /dev/null
    if [[ $? -eq 0 ]]
    then
        PARAM=internal
    else
        PARAM=external
    fi
    echo "start \"$CNTLM\" mode \"$PARAM\"....." > $LOG
else
    PARAM=$1
    echo "restart \"$CNTLM\" mode \"$PARAM\"....." >> $LOG
fi

if [[ "$PARAM" == "internal" ]]
then
    $SDIR/$CNTLM -q -f -a gss -c $SDIR/$INTERNAL >> $LOG 2>&1
elif [[ "$PARAM" == "external" ]]
then
    $SDIR/$CNTLM -q -f -a gss -c $SDIR/$EXTERNAL >> $LOG 2>&1
else
    echo "cannot start \"$CNTLM\" with \"$PARAM\"....." >> $LOG
fi
