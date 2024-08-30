# libforku

### Usage: `forku`

1) Open a new shell and `make run_forku_monitor` to launch the _FUSE_ forku monitor process

2) Run your target process in a separate shell (i.e. `taskset -c 0 ./test.py`)

3) Run `./forku.sh <target_pid> <snapshot_name>` to _forku_ the target process and create a snapshot
file within the forku _sn_ filesystem. Example: `./forku.sh 3145 snap1`.

4) *Important: Let the target process (i.e. `test.py`) run to completion and exit, don't kill it!*

5) You will find your desired snapshot in `sn/<target_pid>/<snapshot_name>` (i.e. `sn/3145/snap1`)

6) To test the validity of the snapshot, run the cat command on it. Example: `cat sn/3145/snap1`

### Usage `execu`

1) Make sure you have a valid snapshot from _forku_ usage section, i.e. `sn/3145/snap1`

2) Source the execu.sh script into the current shell: `. execu.sh`

3) To run _execu_ on a target snapshot and use the current shell as a "_foster parent_" process, run: `execu <snapshot_name>` (i.e. `execu sn/3145/snap1`)
