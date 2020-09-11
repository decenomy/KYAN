#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.kyancore/kyand.pid file instead
kyan_pid=$(<~/.kyancore/testnet3/kyand.pid)
sudo gdb -batch -ex "source debug.gdb" kyand ${kyan_pid}
