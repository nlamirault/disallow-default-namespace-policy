#!/usr/bin/env bats

@test "Accept a valid name" {
	run kwctl run  --request-path test_data/pod_creation.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	# shellcheck disable=SC2046
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Reject invalid name" {
	run kwctl run  --request-path test_data/pod_creation_invalid_name.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	# shellcheck disable=SC2046
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	# shellcheck disable=SC2046
	[ $(expr "$output" : '.*"message":"pod name invalid-pod-name is not accepted".*') -ne 0 ]
 }
