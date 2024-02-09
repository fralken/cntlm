#!/bin/zsh

SDIR=$( cd "$( dirname "$0" )" && pwd )
LAUNCH_AGENTS=~/Library/LaunchAgents
PLIST=cntlm.plist

mkdir -p $LAUNCH_AGENTS
sed "s|{PATH}|$SDIR|g" $SDIR/$PLIST > $LAUNCH_AGENTS/$PLIST
launchctl load $LAUNCH_AGENTS/$PLIST
