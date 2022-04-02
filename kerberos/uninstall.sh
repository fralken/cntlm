#!/bin/zsh

SDIR=$( cd "$( dirname "$0" )" && pwd )
LAUNCH_AGENTS=~/Library/LaunchAgents
PLIST=cntlm.plist
CNTLM=cntlm

if [[ -e $LAUNCH_AGENTS/$PLIST ]]
then
    launchctl unload $LAUNCH_AGENTS/$PLIST
    rm $LAUNCH_AGENTS/$PLIST
    pkill $CNTLM
    pkill $CNTLM
else
    echo "$LAUNCH_AGENTS/$PLIST not found"
fi