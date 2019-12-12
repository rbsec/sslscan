#!/bin/bash

#
# Copyright (C) 2019  Joe Testa <jtesta@positronsecurity.com>
#
# This script (adapted from the ssh-audit project) will set up a docker image with
# multiple SSL/TLS servers.  They are each executed one at a time, and sslscan is run
# against them.  The output of sslscan is compared against the expected output.  If
# they match, the test passes; otherwise the test fails.
#
#
# For debugging purposes, here is a cheat sheet for manually running the docker image:
#
# docker run -p 4443:443 --security-opt seccomp:unconfined -it sslscan-test:1 /bin/bash
#

#
# Running this script with no arguments causes it to build the docker image (if it
# doesn't yet exist), then run all tests.
#
# Running the script with a test number argument (i.e.: './docker_test.sh 2') will
# run the docker image for test #2 only (in the background) and do nothing else.  This
# allows the test itself to be debugged.
#


# This is the docker tag for the image.  If this tag doesn't exist, then we assume the
# image is out of date, and generate a new one with this tag.
IMAGE_VERSION=1

# This is the name of our docker image.
IMAGE_NAME=sslscan-test


# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
REDB="\033[1;31m"    # Red + bold
YELLOWB="\033[1;33m" # Yellow + bold
GREENB="\033[1;32m"  # Green + bold


# Number of processors on this system (used to compile parallel builds).
NUM_PROCS=`/usr/bin/nproc --all 2> /dev/null`
if [[ $NUM_PROCS == '' ]]; then
    NUM_PROCS=4
fi


# Returns 0 if current docker image exists.
function check_if_docker_image_exists {
    images=`docker image ls | egrep "$IMAGE_NAME[[:space:]]+$IMAGE_VERSION"`
}


# Compile all versions of OpenSSL.
function compile_openssl_all {
    compile_openssl '1.0.0'
    compile_openssl '1.0.2'
    compile_openssl '1.1.1'
}


# Compile a specific version of OpenSSL.
function compile_openssl {
    version=$1

    git_tag=
    compile_args=
    precompile_command=
    output_dir=
    compile_num_procs=$NUM_PROCS
    if [[ $version == '1.0.0' ]]; then
	git_tag="OpenSSL_1_0_0-stable"
	compile_args="enable-weak-ssl-ciphers enable-ssl2 zlib no-shared"
	precompile_command="make depend"
	output_dir="openssl_v1.0.0_dir"
	compile_num_procs=1   # Compilation randomly fails when done in parallel.
    elif [[ $version == '1.0.2' ]]; then
	git_tag="OpenSSL_1_0_2-stable"
	compile_args="enable-weak-ssl-ciphers enable-ssl2 zlib"
	precompile_command="make depend"
	output_dir="openssl_v1.0.2_dir"
    elif [[ $version == '1.1.1' ]]; then
	git_tag="OpenSSL_1_1_1-stable"
	compile_args="enable-weak-ssl-ciphers no-shared zlib"
	output_dir="openssl_v1.1.1_dir"
    else
	echo -e "${REDB}Error: OpenSSL v${version} is unknown!${CLR}"
	exit 1
    fi

    # Download OpenSSL from github.
    echo -e "\n${YELLOWB}Downloading OpenSSL v${version}...${CLR}\n"
    git clone -b $git_tag https://github.com/openssl/openssl/ $output_dir

    # Configure and compile it.
    echo -e "\n\n${YELLOWB}Compiling OpenSSL v${version} with \"-j ${compile_num_procs}\"...${CLR}"
    pushd $output_dir
    ./config $compile_args
    if [[ $precompile_command != '' ]]; then $precompile_command; fi
    make -j $compile_num_procs

    # Ensure that the 'openssl' command-line tool was built.
    if [[ ! -f "apps/openssl" ]]; then
	echo -e "${REDB}Error: compilation failed!  apps/openssl not found.${CLR}\n\nStrangely, sometimes OpenSSL v1.0.0 fails for no reason; simply running this script again and changing nothing fixes the problem.\n\n"
	exit 1
    fi

    # Copy the 'openssl' app to the top-level docker building dir as, e.g. 'openssl_prog_v1.0.0'.  Then we can delete the source code directory and move on.
    cp "apps/openssl" "../openssl_prog_v${version}"
    popd

    # Delete the source code directory now that we built the 'openssl' tool and moved it out.
    rm -rf $output_dir
    echo -e "\n\n${YELLOWB}Compilation of v${version} finished.${CLR}\n\n"
}


# Creates a new docker image.
function create_docker_image {
    # Create a new temporary directory.
    TMP_DIR=`mktemp -d /tmp/sslscan-docker-XXXXXXXXXX`

    # Copy the Dockerfile and all files in the test/docker/ dir to our new temp directory.
    find docker_test -maxdepth 1 -type f | xargs cp -t $TMP_DIR

    # Make the temp directory our working directory for the duration of the build
    # process.
    pushd $TMP_DIR > /dev/null

    # Compile the versions of OpenSSL.
    compile_openssl_all

    # Now build the docker image!
    echo -e "${YELLOWB}Creating docker image...${CLR}"
    docker build --tag $IMAGE_NAME:$IMAGE_VERSION .
    echo -e "${YELLOWB}Docker image creation complete.${CLR}"

    popd > /dev/null
    rm -rf $TMP_DIR
}


# Runs all tests with the debug flag disabled.
function run_tests {
    run_test_1 "0"
    run_test_2 "0"
    run_test_3 "0"
    run_test_4 "0"
    run_test_5 "0"
    run_test_6 "0"
    run_test_7 "0"
    run_test_8 "0"
    run_test_9 "0"
    run_test_10 "0"
    run_test_11 "0"
}


# Mostly default v1.0.2 (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2)
function run_test_1 {
    run_test $1 '1' "/openssl_v1.0.2/openssl s_server -accept 443 -dhparam /etc/ssl/dhparams_2048.pem -key /etc/ssl/key_2048.pem -cert /etc/ssl/cert_2048.crt" ""
}


# SSLv2 with 1024-bit certificate & DH parameters.
function run_test_2 {
    run_test $1 '2' "/openssl_v1.0.2/openssl s_server -ssl2 -accept 443 -dhparam /etc/ssl/dhparams_1024.pem -key /etc/ssl/key_1024.pem -cert /etc/ssl/cert_1024.crt" ""
}


# SSLv3 with 1024-bit certificate & DH parameters.
function run_test_3 {
    run_test $1 '3' "/openssl_v1.0.2/openssl s_server -ssl3 -accept 443 -dhparam /etc/ssl/dhparams_1024.pem -key /etc/ssl/key_1024.pem -cert /etc/ssl/cert_1024.crt" ""
}


# Mostly default v1.1.1.
function run_test_4 {
    run_test $1 '4' "/openssl_v1.1.1/openssl s_server -accept 443 -dhparam /etc/ssl/dhparams_3072.pem -key /etc/ssl/key_3072.pem -cert /etc/ssl/cert_3072.crt" ""
}


# All ciphers with SSLv2 through TLSv1.2 with 1024-bit certificate & DH parameters.
function run_test_5 {
    run_test $1 '5' "/openssl_v1.0.2/openssl s_server -cipher ALL -accept 443 -dhparam /etc/ssl/dhparams_1024.pem -key /etc/ssl/key_1024.pem -cert /etc/ssl/cert_1024.crt" ""
}


# TLSv1.3 with all ciphers.
function run_test_6 {
    run_test $1 '6' "/openssl_v1.1.1/openssl s_server -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256 -accept 443 -dhparam /etc/ssl/dhparams_3072.pem -key /etc/ssl/key_3072.pem -cert /etc/ssl/cert_3072.crt" ""
}


# Default v1.0.0.
function run_test_7 {
    run_test $1 '7' "/openssl_v1.0.0/openssl s_server -accept 443 -key /etc/ssl/key_3072.pem -cert /etc/ssl/cert_3072.crt" ""
}


# v1.0.0 with 'ALL:eNULL' ciphers.
function run_test_8 {
    run_test $1 '8' "/openssl_v1.0.0/openssl s_server -accept 443 -cipher ALL:eNULL -key /etc/ssl/key_3072.pem -cert /etc/ssl/cert_3072.crt" ""
}


# Runs nginx with client certificate checking (signed by the CA in docker_test/ca_cert.pem).  sslscan will connect and make an HTTP request (--http).  The HTTP response code should be 200 to signify that the certificate was accepted.  Otherwise, nginx returns HTTP code 400 if no client certificates were presented.
function run_test_9 {
    run_test $1 '9' "/usr/sbin/nginx -c /etc/nginx/nginx_test9.conf" "--no-fallback --no-renegotiation --no-compression --no-heartbleed --certs=docker_test/cert_3072.crt --pk=docker_test/key_3072.pem --http"
}


# Runs nginx with client certificate checking, just as above.  Except this time, we connect with no certificate.  The HTTP response code should be "400 Bad Request".
function run_test_10 {
    run_test $1 '10' "/usr/sbin/nginx -c /etc/nginx/nginx_test9.conf" "--no-fallback --no-renegotiation --no-compression --no-heartbleed --http"
}


# Makes an OCSP request to www.amazon.com.  The horrible Perl command that comes after it will filter out the timestamps and other variable data from the response, otherwise the diff would fail.
function run_test_11 {
    run_test_internet '11' "./sslscan --ocsp --no-ciphersuites --no-fallback --no-renegotiation --no-compression --no-heartbleed --no-check-certificate www.amazon.com | perl -pe 'BEGIN{undef $/;} s/Connected to .+?$/Connected to\033[0m/smg; s/Responder Id: .+?$/Responder Id:/smg; s/Produced At: .+?$/Produced At:/smg; s/Hash Algorithm: .+?$/Hash Algorithm:/smg; s/Issuer Name Hash: .+?$/Issuer Name Hash:/smg; s/Issuer Key Hash: .+?$/Issuer Key Hash:/smg; s/Serial Number: .+?$/Serial Number:/smg; s/This Update: .+?$/This Update:/smg; s/Next Update: .+?$/Next Update:/smg; s/Response Single Extensions:.+?\n\n/\n\n/smg;'"
}


# Run a test.  Set the first argument to '1' to enable test debugging.
# Second argument is the test number to run.  Third argument is the executable and
# its args to be run inside the container..
function run_test {
    debug=$1
    test_number=$2
    server_exec=$3
    sslscan_additional_args=$4

    test_result_stdout="${TEST_RESULT_DIR}/test_${test_number}.txt"
    expected_result_stdout="docker_test/expected_output/test_${test_number}.txt"

    # Run the container in the background.  Route port 4443 on the outside to port 443 on the inside.
    cid=`docker run -d -p 4443:443 -t ${IMAGE_NAME}:${IMAGE_VERSION} ${server_exec}`
    if [[ $? != 0 ]]; then
	echo -e "${REDB}Failed to run docker image! (exit code: $?)${CLR}"
	exit 1
    fi

    # If debugging is enabled, just run the container.  Don't do any output comparison.
    if [[ $debug == 1 ]]; then
	echo -e "\nExecuted in container: ${server_exec}\n\nTerminate container with: docker container stop -t 0 ${cid}\n\nHint: run sslscan against localhost on port 4443, not 443.\n"
	return
    fi

    # Run sslscan and cut out the first two lines.  Those contain the version number
    # and local version of OpenSSL, which can change over time (and when they do, this
    # would break the test if they were left in).
    ./sslscan $sslscan_additional_args localhost:4443 | tail -n +3 > $test_result_stdout
    if [[ $? != 0 ]]; then
	echo -e "${REDB}Failed to run sslscan! (exit code: $?)${CLR}"
	docker container stop -t 0 $cid > /dev/null
	exit 1
    fi

    # Stop the container now that we captured the sslscan output.
    docker container stop -t 0 $cid > /dev/null
    if [[ $? != 0 ]]; then
       echo -e "${REDB}Failed to stop docker container ${cid}! (exit code: $?)${CLR}"
       exit 1
    fi

    # If the expected output file doesn't exist, give the user all the info we have so they can fix this.
    if [[ ! -f ${expected_result_stdout} ]]; then
	test_result_stdout_actual=`cat ${test_result_stdout}`
	echo -e "\n${REDB}Error:${CLR} expected output file for test #${test_number} not found (${expected_result_stdout}).  Actual test result is below.  Manually verify that this output is correct; if so, then copy it to the expected test file path with:\n\n  $ cp ${test_result_stdout} ${expected_result_stdout}\n\n------\n${test_result_stdout_actual}\n"
	exit 1
    fi

    # Compare the actual output to the expected output.  Any discrepency results in test failure.
    diff=`diff -u ${expected_result_stdout} ${test_result_stdout}`
    if [[ $? != 0 ]]; then
	echo -e "Test #${test_number} ${REDB}FAILED${CLR}.\n\n${diff}\n"
	exit 1
    fi

    echo -e "Test #${test_number} ${GREEN}passed${CLR}."
}


# Instead of spinning up a docker instance, this will run a test using a host on the
# public Internet.
function run_test_internet {
    test_number=$1
    command=$2

    test_result_stdout="${TEST_RESULT_DIR}/test_${test_number}.txt"
    expected_result_stdout="docker_test/expected_output/test_${test_number}.txt"

    `/bin/bash -c "${command} | tail -n +3 > ${test_result_stdout}"`
    if [[ $? != 0 ]]; then
	echo -e "${REDB}Failed to run sslscan! (exit code: $?)${CLR}"
	docker container stop -t 0 $cid > /dev/null
	exit 1
    fi

    # If the expected output file doesn't exist, give the user all the info we have so they can fix this.
    if [[ ! -f ${expected_result_stdout} ]]; then
	test_result_stdout_actual=`cat ${test_result_stdout}`
	echo -e "\n${REDB}Error:${CLR} expected output file for test #${test_number} not found (${expected_result_stdout}).  Actual test result is below.  Manually verify that this output is correct; if so, then copy it to the expected test file path with:\n\n  $ cp ${test_result_stdout} ${expected_result_stdout}\n\n------\n${test_result_stdout_actual}\n"
	exit 1
    fi

    # Compare the actual output to the expected output.  Any discrepency results in test failure.
    diff=`diff -u ${expected_result_stdout} ${test_result_stdout}`
    if [[ $? != 0 ]]; then
	echo -e "Test #${test_number} ${REDB}FAILED${CLR}.\n\n${diff}\n"
	exit 1
    fi

    echo -e "Test #${test_number} ${GREEN}passed${CLR}."
}


# First check if docker is functional.
docker version > /dev/null
if [[ $? != 0 ]]; then
    echo -e "${REDB}Error: 'docker version' command failed (error code: $?).  Is docker installed and functioning?${CLR}"
    exit 1
fi

# Make sure sslscan has been built.
if [[ ! -f sslscan ]]; then
    echo -e "${REDB}Error: sslscan executable not found.  Build it first!${CLR}"
    exit 1
fi

# If the user specified a test number to debug...
debug_test_number=0
if [[ $# == 1 ]]; then
   debug_test_number=$1
   debug_test_number=$((debug_test_number + 0)) # Effectively, convert this to a number.
fi

# Check if the docker image is the most up-to-date version.  If not, create it.
check_if_docker_image_exists
if [[ $? == 0 ]]; then
    echo -e "\n${GREEN}Docker image $IMAGE_NAME:$IMAGE_VERSION already exists.${CLR}"
else
    echo -e "\nCreating docker image $IMAGE_NAME:$IMAGE_VERSION..."
    create_docker_image
    echo -e "\n${GREEN}Done creating docker image!${CLR}"
fi

# Create a temporary directory to write test results to.
TEST_RESULT_DIR=`mktemp -d /tmp/sslscan_test-results_XXXXXXXXXX`

# If the user wants to run a specific test with debugging enabled, do that then exit.
if [[ $debug_test_number > 0 ]]; then
    eval "run_test_${debug_test_number} 1"
    exit 0
fi

# Now run all the tests.
echo -e "\nRunning all tests..."
run_tests

# The test functions above will terminate the script on failure, so if we reached here,
# all tests are successful.
echo -e "\n${GREENB}ALL TESTS PASS!${CLR}\n"

rm -rf $TEST_RESULT_DIR
exit 0
