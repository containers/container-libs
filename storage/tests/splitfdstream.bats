#!/usr/bin/env bats

load helpers

# start_server launches the json-rpc-server in the background, fully
# detached from bats file descriptors so it won't block test output.
# Sets SERVER_PID to the actual binary PID.
start_server() {
	local extra_args=("$@")
	${STORAGE_BINARY} --graph ${TESTDIR}/root --run ${TESTDIR}/runroot \
		--storage-driver ${STORAGE_DRIVER} \
		${STORAGE_OPTION:+--storage-opt=${STORAGE_OPTION}} \
		json-rpc-server "${extra_args[@]}" \
		</dev/null >/dev/null 2>&1 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
	SERVER_PID=$!
}

# stop_server kills the json-rpc-server and waits for it to exit.
stop_server() {
	if [[ -n "$SERVER_PID" ]]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
		SERVER_PID=
	fi
}

# Override teardown to stop the server before the default teardown runs
# storage wipe.  If the server is still running it holds the store lock
# and wipe would deadlock.
teardown() {
	stop_server
	run storage wipe
	if [[ $status -ne 0 ]] ; then
		echo "$output"
	fi
	run storage shutdown
	if [[ $status -ne 0 ]] ; then
		echo "$output"
	fi
	rm -fr ${TESTDIR}
}

@test "splitfdstream json-rpc-server and apply-splitfdstream" {
	case "$STORAGE_DRIVER" in
	overlay*)
		;;
	*)
		skip "driver $STORAGE_DRIVER does not support splitfdstream"
		;;
	esac

	# Create and populate a test layer
	populate

	# Get the socket path from runroot
	local runroot=`storage status 2>&1 | awk '/^Run Root:/{print $3}'`
	local socket_path="$runroot/json-rpc.sock"

	# Start the JSON-RPC server in the background
	start_server --socket "$socket_path"

	# Wait for socket to be created (max 10 seconds)
	local count=0
	while [[ ! -S "$socket_path" && $count -lt 50 ]]; do
		sleep 0.2
		count=$((count + 1))
	done

	# Check that the socket exists
	[ -S "$socket_path" ]

	# Create a new layer using apply-splitfdstream
	# This should connect to our JSON-RPC server and fetch the layer
	run storage --debug=false apply-splitfdstream --socket "$socket_path" "$lowerlayer"
	echo "apply-splitfdstream output: $output"
	[ "$status" -eq 0 ]
	[ "$output" != "" ]

	applied_layer="$output"

	# Verify the layer was created
	run storage --debug=false layers
	[ "$status" -eq 0 ]
	[[ "$output" =~ "$applied_layer" ]]

	# Check that we can mount the applied layer
	run storage --debug=false mount "$applied_layer"
	[ "$status" -eq 0 ]
	[ "$output" != "" ]
	local applied_mount="$output"

	# Verify some expected content exists (from populate function)
	[ -f "$applied_mount/layer1file1" ]
	[ -f "$applied_mount/layer1file2" ]
	[ -d "$applied_mount/layerdir1" ]

	# Unmount the layer
	run storage unmount "$applied_layer"
	[ "$status" -eq 0 ]

	# Kill the server before teardown runs storage wipe (which needs the store lock)
	stop_server
}

@test "splitfdstream server socket path uses runroot" {
	case "$STORAGE_DRIVER" in
	overlay*)
		;;
	*)
		skip "driver $STORAGE_DRIVER does not support splitfdstream"
		;;
	esac

	# Get the expected socket path from runroot
	local runroot=`storage status 2>&1 | awk '/^Run Root:/{print $3}'`
	local expected_socket="$runroot/json-rpc.sock"

	# Start the JSON-RPC server in the background
	start_server

	# Wait for socket to be created (max 10 seconds)
	local count=0
	while [[ ! -S "$expected_socket" && $count -lt 50 ]]; do
		sleep 0.2
		count=$((count + 1))
	done

	# Verify the socket is created in the correct location
	[ -S "$expected_socket" ]

	# Kill the server before teardown runs storage wipe (which needs the store lock)
	stop_server
}
