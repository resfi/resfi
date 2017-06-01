#!/bin/bash
SESSION=$USER

tmux -2 new-session -d -s $SESSION

# Setup a window for tailing log files
tmux new-window -t $SESSION:1 -n 'ResFi Demo'
tmux split-window -h
tmux select-pane -t 0
tmux send-keys 'ssh 192.168.200.29' C-m
tmux send-keys 'cd resfi' C-m
tmux send-keys 'watch -n 0,1 "tail -n10 /tmp/resfi_console_demo.log"' C-m
tmux select-pane -t 1
tmux send-keys "ssh 192.168.200.10" C-m
tmux send-keys 'cd resfi' C-m
tmux send-keys 'watch -n 0,1 "tail -n10 /tmp/resfi_console_demo.log"' C-m
tmux split-window -v
tmux send-keys "ssh 192.168.200.15" C-m
tmux send-keys 'cd resfi' C-m
tmux send-keys 'watch -n 0,1 "tail -n10 /tmp/resfi_console_demo.log"' C-m
tmux select-pane -t 0
tmux split-window -v
tmux send-keys "ssh 192.168.200.40" C-m
tmux send-keys 'cd resfi' C-m
tmux send-keys 'watch -n 0,1 "tail -n10 /tmp/resfi_console_demo.log"' C-m

# Set default window
tmux select-window -t $SESSION:1

# Attach to session
tmux -2 attach-session -t $SESSION
