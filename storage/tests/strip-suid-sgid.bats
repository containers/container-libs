#!/usr/bin/env bats

load helpers

@test "strip-suid-sgid via staging directory" {
	case "$STORAGE_DRIVER" in
	overlay*)
		;;
	*)
		skip "driver $STORAGE_DRIVER does not support diff-from-staging-directory"
		;;
	esac

	# Create source directory with SUID/SGID files.
	SRC=$TESTDIR/source
	mkdir -p $SRC
	createrandom $SRC/suid_file
	chmod 4755 $SRC/suid_file
	createrandom $SRC/sgid_file
	chmod 2755 $SRC/sgid_file
	createrandom $SRC/suid_sgid_file
	chmod 6755 $SRC/suid_sgid_file
	createrandom $SRC/normal_file
	chmod 0755 $SRC/normal_file

	local sconf=$TESTDIR/storage.conf

	local root=`storage status 2>&1 | awk '/^Root:/{print $2}'`
	local runroot=`storage status 2>&1 | awk '/^Run Root:/{print $3}'`

	cat >$sconf <<EOF
[storage]
driver="overlay"
graphroot="$root"
runroot="$runroot"

[storage.options]
strip_suid_sgid = true

[storage.options.pull_options]
enable_partial_images = "true"
convert_images = "true"
EOF

	# Create a layer.
	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} create-layer
	[ "$status" -eq 0 ]
	[ "$output" != "" ]
	layer="$output"

	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} applydiff-using-staging-dir $layer $SRC
	[ "$status" -eq 0 ]

	name=suid-test-image
	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} create-image --name $name $layer
	[ "$status" -eq 0 ]

	ctrname=suid-test-container
	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} create-container --name $ctrname $name
	[ "$status" -eq 0 ]

	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} mount $ctrname
	[ "$status" -eq 0 ]
	mount="$output"

	# SUID bit (04000) should be stripped.
	run stat -c %a $mount/suid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# SGID bit (02000) should be stripped.
	run stat -c %a $mount/sgid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# Both SUID and SGID should be stripped.
	run stat -c %a $mount/suid_sgid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# Normal file should be unchanged.
	run stat -c %a $mount/normal_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]
}

@test "strip-suid-sgid via applydiff" {
	# The test needs "tar".
	if test -z "$(which tar 2> /dev/null)" ; then
		skip "need tar"
	fi

	# Create source files with SUID/SGID bits.
	run storage --debug=false create-layer
	[ "$status" -eq 0 ]
	[ "$output" != "" ]
	srclayer="$output"

	run storage --debug=false mount $srclayer
	[ "$status" -eq 0 ]
	[ "$output" != "" ]
	srcmount="$output"

	createrandom "$srcmount"/suid_file
	chmod 4755 "$srcmount"/suid_file
	createrandom "$srcmount"/sgid_file
	chmod 2755 "$srcmount"/sgid_file
	createrandom "$srcmount"/suid_sgid_file
	chmod 6755 "$srcmount"/suid_sgid_file
	createrandom "$srcmount"/normal_file
	chmod 0755 "$srcmount"/normal_file

	run storage --debug=false unmount $srclayer
	[ "$status" -eq 0 ]

	# Extract as tar.
	storage diff -u -f $TESTDIR/suid.tar $srclayer

	# Delete source layer.
	storage delete-layer $srclayer

	# Create config with strip_suid_sgid enabled.
	local sconf=$TESTDIR/storage.conf

	local root=`storage status 2>&1 | awk '/^Root:/{print $2}'`
	local runroot=`storage status 2>&1 | awk '/^Run Root:/{print $3}'`

	cat >$sconf <<EOF
[storage]
driver="$STORAGE_DRIVER"
graphroot="$root"
runroot="$runroot"

[storage.options]
strip_suid_sgid = true
EOF

	# Create new layer and apply the tar diff.
	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} create-layer
	[ "$status" -eq 0 ]
	[ "$output" != "" ]
	layer="$output"

	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} applydiff -f $TESTDIR/suid.tar $layer
	[ "$status" -eq 0 ]

	CONTAINERS_STORAGE_CONF=$sconf run ${STORAGE_BINARY} mount $layer
	[ "$status" -eq 0 ]
	mount="$output"

	# SUID bit should be stripped.
	run stat -c %a $mount/suid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# SGID bit should be stripped.
	run stat -c %a $mount/sgid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# Both SUID and SGID should be stripped.
	run stat -c %a $mount/suid_sgid_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]

	# Normal file should be unchanged.
	run stat -c %a $mount/normal_file
	[ "$status" -eq 0 ]
	[ "$output" = "755" ]
}
