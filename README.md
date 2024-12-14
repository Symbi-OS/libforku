# libforku

## Background and Goals

The forku/execu project is designed to explore advanced process management and snapshotting techniques, focusing on creating and restoring the execution
state of running processes. A "snapshot" in this context represents a lightweight kernel primitive that encapsulates the page table, memory information,
and hardware registers of a running process at a specific point in time. These snapshot primitives, referred to as "doppelgangers," serve as reusable templates
for initializing new processes from a predefined state. This capability has broad applications, such as addressing cold start latency in
Function-as-a-Service (FaaS) systems, enabling efficient checkpointing for "checkpoint-restart" debugging workflows, and serving as state vectors for
optimizing systems through computational caching techniques.

## Implementation Details

The implementation consists of two primary components. Due to current limitations of dynamic privilege, certain modifications are required at the kernel
source code level. One aspect of the implementation focuses on these kernel changes, exposing new functions that can be invoked from userspace using
dynamic privilege. The other aspect involves userspace utilities that orchestrate the forku and execu operations by invoking these kernel routines.
Central to this design is a "monitor" daemon process running in userspace, which facilitates forku and execu functionality.

For instance, if an arbitrary process X is running, a separate process (such as a shell process) can send a request to the monitor process with the PID
of process X. The monitor then creates and registers a frozen snapshot of process X at that moment. Importantly, the original process X can continue
running or even exit, while the snapshot remains preserved in memory. This snapshot is exposed to the user as a file through a FUSE-powered filesystem,
enabling straightforward access and management.

At a later time, the user can send an execu request to the monitor, specifying the path to the snapshot file and the PID of a "foster" parent process.
The execu operation then embeds the snapshot’s memory and register state into the existing process, integrating it with the foster process’s pre-existing
file descriptor table, environment, context information, and connected resources.

*Note*: Ideally, a snapshot is designed as a lightweight primitive, encapsulating only mm mappings and thread information. However, the current
implementation includes additional environment-related details, such as PID information, signal states, and parent process metadata. This additional
complexity is expected to be streamlined in future iterations.

### Kernel Changes

## Usage: `forku`

1) Open a new shell and `make run_forku_monitor` to launch the _FUSE_ forku monitor process

2) Run your target process in a separate shell (i.e. `taskset -c 0 ./test.py`)

3) Run `./forku.sh <target_pid> <snapshot_name>` to _forku_ the target process and create a snapshot
file within the forku _sn_ filesystem. Example: `./forku.sh 3145 snap1`.

4) *Important: Let the target process (i.e. `test.py`) run to completion and exit, don't kill it!*

5) You will find your desired snapshot in `sn/<target_pid>/<snapshot_name>` (i.e. `sn/3145/snap1`)

6) To test the validity of the snapshot, run the cat command on it. Example: `cat sn/3145/snap1`

## Usage `execu`

1) Make sure you have a valid snapshot from _forku_ usage section, i.e. `sn/3145/snap1`

2) Source the execu.sh script into the current shell: `. execu.sh`

3) To run _execu_ on a target snapshot and use the current shell as a "_foster parent_" process, run: `execu <snapshot_name>` (i.e. `execu sn/3145/snap1`)
