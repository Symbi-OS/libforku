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

`forku_copy_process`:
This function mirrors the behavior of the standard `copy_process` but includes additional logic to save the `gs` and `fs` base values. This prevents
corruption in the target process since the current pointer is impersonated by the caller (the monitor daemon) during the snapshot operation.

`forku_copy_process_execu_version`:
Similar to `forku_copy_process`, this function creates a process copy, but with one critical difference: the environment data is sourced from the `foster_parent`
task struct parameter, enabling the reuse of an existing process context for snapshot restoration.

`forku_copy_thread`:
This function replicates the functionality of `copy_thread` while omitting the call to `save_current_fsgs()`. This omission is necessary to avoid corruption
caused by the impersonated `current` value when creating a new thread context.

`execu_task`:
The primary function for process restoration, `execu_task` takes a snapshot’s `task_struct*` as input. Its purpose is to "exec" the process referenced by
`current` into the snapshot. This is achieved by installing the snapshot’s page table and memory mappings, and updating the thread and register state to
match the snapshot.

### Userspace Changes

The `forku_util.c` file encapsulates a userspace utility designed to interact directly with the forku library and kernel functions. It provides a
lightweight interface for partially forking a target process, effectively capturing its state and enabling further manipulation. The purpose of this
utility is to give users or higher-level systems a way to directly invoke the forku functionality without needing to interact with kernel-level code directly.

When run, `forku_util` takes a target process's PID as input, partially forks the process using the `forku_pid()` library function, and prepares the forked task for further operations. It employs dynamic privilege escalation (`sym_elevate()` and `sym_lower()`) to execute privileged operations securely. The resulting forked task is a copy of the target process, with its state encapsulated and ready for further snapshotting or scheduling. This utility includes placeholders for extending functionality, such as saving snapshots or cleaning up forked task memory, which will need to be addressed as the project evolves. It is primarily intended for debugging, experimentation, or providing a basis for higher-level operations like snapshot registration through the forku_monitord daemon.

The `forku_monitord.c` file acts as the monitor daemon mentioned earlier. It manages a FUSE-powered filesystem, exposing process snapshots as accessible files. This daemon handles requests to create snapshots, retrieve their metadata, and manage the lifecycle of these snapshots. It maintains an internal registry of PIDs and their associated snapshots, ensuring snapshots are tracked and managed efficiently. When a user creates a new snapshot, the daemon interfaces with the forku library to perform the necessary kernel-level operations, such as forking a process or registering its state. These snapshots can then be accessed as files within the FUSE filesystem, making them easy to work with for users or other system components.

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
