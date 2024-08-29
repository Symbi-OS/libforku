#!/bin/bash

function __execu() {
  local path=$1
  local pid=$BASHPID
  shift
  echo "DBG> pid: $pid"
  #read
  #echo "$pid" >> $path
  i=1
  while ((i > 0)); do
      ((i++))
  done
}

function execu() {
  echo "toplevel pid: $$"
  ( __execu $@ )
}

export -f __execu
export -f execu
