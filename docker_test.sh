#!/bin/bash

#
# Copyright (C) 2019-2020  Joe Testa <jtesta@positronsecurity.com>
#
# This script (adapted from the ssh-audit project) will set up a docker image with
# multiple SSL/TLS servers.  They are each executed one at a time, and sslscan is run
# against them.  The output of sslscan is compared against the expected output.  If
# they match, the test passes; otherwise the test fails.
#
#
# For debugging purposes, here is a cheat sheet for manually running the docker image:
#
# docker run -p 4443:443 --security-opt seccomp:unconfined -it sslscan-test:3 /bin/bash
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
IMAGE_VERSION=3

# This is the name of our docker image.
IMAGE_NAME=sslscan-test


# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
REDB="\033[1;31m"    # Red + bold
YELLOWB="\033[1;33m" # Yellow + bold
GREENB="\033[1;32m"  # Green + bold

# Set to 0 if any test fails.
all_passed=1


# Number of processors on this system (used to compile parallel builds).
NUM_PROCS=`/usr/bin/nproc --all 2> /dev/null`
if [[ $NUM_PROCS == '' ]]; then
    NUM_PROCS=4
fi


# Returns 0 if current docker image exists.
function check_if_docker_image_exists {
    images=`docker image ls | egrep "$IMAGE_NAME[[:space:]]+$IMAGE_VERSION"`
}


# Compile all version of GnuTLS.
function compile_gnutls_all {
    compile_gnutls '3.6.11.1'
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
    git clone --depth 1 -b $git_tag https://github.com/openssl/openssl/ $output_dir

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


# Compile a specific version of GnuTLS.
function compile_gnutls {
    gnutls_version=$1

    gnutls_url=
    nettle_url=
    gnutls_expected_sha256=
    nettle_expected_sha256=
    gnutls_filename=
    nettle_filename=
    gnutls_source_dir=
    nettle_source_dir=
    nettle_version=
    compile_num_procs=$NUM_PROCS
    compile_nettle=0
    if [[ $gnutls_version == '3.6.11.1' ]]; then
	gnutls_url=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.11.1.tar.xz
	gnutls_expected_sha256=fbba12f3db9a55dbf027e14111755817ec44b57eabec3e8089aac8ac6f533cf8
	gnutls_filename=gnutls-3.6.11.1.tar.xz
	gnutls_source_dir=gnutls-3.6.11.1
	nettle_version=3.5.1
	nettle_url=https://ftp.gnu.org/gnu/nettle/nettle-3.5.1.tar.gz
	nettle_expected_sha256=75cca1998761b02e16f2db56da52992aef622bf55a3b45ec538bc2eedadc9419
	nettle_filename=nettle-3.5.1.tar.gz
	nettle_source_dir=nettle-3.5.1
	compile_nettle=1
    else
	echo -e "${REDB}Error: GnuTLS v${gnutls_version} is unknown!${CLR}"
	exit 1
    fi

    # Download GnuTLS.
    echo -e "\n${YELLOWB}Downloading GnuTLS v${gnutls_version}...${CLR}\n"
    wget $gnutls_url

    # Download nettle.
    echo -e "\n${YELLOWB}Downloading nettle library v${nettle_version}...${CLR}\n"
    wget $nettle_url

    # Check the SHA256 hashes.
    gnutls_actual_sha256=`sha256sum ${gnutls_filename} | cut -f1 -d" "`
    nettle_actual_sha256=`sha256sum ${nettle_filename} | cut -f1 -d" "`

    if [[ ($gnutls_actual_sha256 != $gnutls_expected_sha256) || ($nettle_actual_sha256 != $nettle_expected_sha256) ]]; then
	echo -e "${REDB}GnuTLS/nettle actual hashes differ from expected hashes! ${CLR}\n"
	echo -e "\tGnuTLS expected hash: ${gnutls_expected_sha256}\n"
	echo -e "\tGnuTLS actual hash:   ${gnutls_actual_sha256}\n"
	echo -e "\tnettle expected hash: ${nettle_expected_sha256}\n"
	echo -e "\tnettle actual hash:   ${nettle_actual_sha256}\n\n"
	exit 1
    else
	echo -e "${GREEN}Hashes verified.${CLR}\n"
    fi

    tar xJf $gnutls_filename

    if [[ $compile_nettle == 1 ]]; then
	tar xzf $nettle_filename
	mv $nettle_source_dir nettle

	# Configure and compile nettle.
	echo -e "\n\n${YELLOWB}Compiling nettle v${nettle_version} with \"-j ${compile_num_procs}\"...${CLR}"
	pushd nettle
	./configure && make -j $compile_num_procs

	if [[ ! -f libnettle.so || ! -f libhogweed.so ]]; then
	    echo -e "${REDB}Error: compilation failed!  libnettle.so and/or libhogweed.so not found.${CLR}"
	    exit 1
	fi
	popd
    fi

    # Configure and compile GnuTLS.
    echo -e "\n\n${YELLOWB}Compiling GnuTLS v${gnutls_version} with \"-j ${compile_num_procs}\"...${CLR}"
    pushd $gnutls_source_dir
    nettle_source_dir_abs=`readlink -m ../nettle`
    nettle_parent_dir=`readlink -m ..`
    NETTLE_CFLAGS=-I${nettle_parent_dir} NETTLE_LIBS="-L${nettle_source_dir_abs} -lnettle" HOGWEED_CFLAGS=-I${nettle_parent_dir} HOGWEED_LIBS="-L${nettle_source_dir_abs} -lhogweed" ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-guile
    make CFLAGS=-I${nettle_parent_dir} LDFLAGS="-L${nettle_source_dir_abs} -lhogweed -lnettle" -j $compile_num_procs

    # Ensure that the gnutls-serv and gnutls-cli tools were built
    if [[ (! -f "src/.libs/gnutls-cli") || (! -f "src/.libs/gnutls-serv") ]]; then
	echo -e "${REDB}Error: compilation failed!  gnutls-cli and/or gnutls-serv not found.${CLR}\n"
	exit 1
    fi

    # Copy the gnutls-cli and gnutls-serv apps to the top-level docker building dir as, e.g. 'gnutls-cli-v3.6.11.1'.  Then we can delete the source code directory and move on.
    cp "lib/.libs/libgnutls.so" "../libgnutls.so.30"
    cp "src/.libs/gnutls-cli" "../gnutls-cli-v${gnutls_version}"
    cp "src/.libs/gnutls-serv" "../gnutls-serv-v${gnutls_version}"
    cp "${nettle_source_dir_abs}/libhogweed.so" "../libhogweed.so.5"
    cp "${nettle_source_dir_abs}/libnettle.so" "../libnettle.so.7"
    popd


    # Delete the source code directory now that we built the tools and moved them out.
    rm -rf ${gnutls_source_dir}
    echo -e "\n\n${YELLOWB}Compilation of GnuTLS v${gnutls_version} finished.${CLR}\n\n"
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

    # Compile the versions of GnuTLS.
    compile_gnutls_all

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
    run_test_12 "0"
    run_test_13 "0"
    run_test_14 "0"
    run_test_15 "0"
    run_test_16 "0"
    run_test_17 "0"
    run_test_18 "0"
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
    #run_test $1 '9' "/usr/sbin/nginx -c /etc/nginx/nginx_test9.conf" "--no-fallback --no-renegotiation --no-compression --no-heartbleed --certs=docker_test/cert_3072.crt --pk=docker_test/key_3072.pem --http"
    echo "Test #9 skipped."
}


# Runs nginx with client certificate checking, just as above.  Except this time, we connect with no certificate.  The HTTP response code should be "400 Bad Request".
function run_test_10 {
    #run_test $1 '10' "/usr/sbin/nginx -c /etc/nginx/nginx_test9.conf" "--no-fallback --no-renegotiation --no-compression --no-heartbleed --http"
    echo "Test #10 skipped."
}


# Makes an OCSP request to www.amazon.com.  The horrible Perl command that comes after it will filter out the timestamps and other variable data from the response, otherwise the diff would fail.
function run_test_11 {
    run_test_internet '11' "./sslscan --ocsp --no-ciphersuites --no-fallback --no-renegotiation --no-compression --no-heartbleed --no-check-certificate --no-groups --no-sigs www.amazon.com | perl -pe 'BEGIN{undef $/;} s/Connected to .+?$/Connected to\033[0m/smg; s/Responder Id: .+?$/Responder Id:/smg; s/Produced At: .+?$/Produced At:/smg; s/Hash Algorithm: .+?$/Hash Algorithm:/smg; s/Issuer Name Hash: .+?$/Issuer Name Hash:/smg; s/Issuer Key Hash: .+?$/Issuer Key Hash:/smg; s/Serial Number: .+?$/Serial Number:/smg; s/This Update: .+?$/This Update:/smg; s/Next Update: .+?$/Next Update:/smg; s/Response Single Extensions:.+?\n\n/\n\n/smg;'"
}


# 512-bit DH, 512-bit RSA key with MD5 signature.
function run_test_12 {
    run_test $1 '12' "/openssl_v1.0.0/openssl s_server -accept 443 -dhparam /etc/ssl/dhparams_512.pem -key /etc/ssl/key_512.pem -cert /etc/ssl/cert_512.crt" ""
}


# Default GnuTLS.
function run_test_13 {
    run_test $1 '13' "/gnutls-3.6.11.1/gnutls-serv -p 443 --x509certfile=/etc/ssl/cert_3072.crt --x509keyfile=/etc/ssl/key_3072.pem" ""
}


# GnuTLS with only TLSv1.2 and TLSv1.3, and secp521r1 and ffdhe8192 groups.
function run_test_14 {
    run_test $1 '14' "/gnutls-3.6.11.1/gnutls-serv -p 443 --priority=NORMAL:-VERS-TLS1.1:-VERS-TLS1.0:-GROUP-X25519:-GROUP-SECP256R1:-GROUP-SECP384R1:-GROUP-FFDHE2048:-GROUP-FFDHE3072:-GROUP-FFDHE4096:-GROUP-FFDHE6144 --x509certfile=/etc/ssl/cert_3072.crt --x509keyfile=/etc/ssl/key_3072.pem" ""
}


# GnuTLS with an ECDSA certificate (secp256r1 / NIST P-256).
function run_test_15 {
    run_test $1 '15' "/gnutls-3.6.11.1/gnutls-serv -p 443 --x509certfile=/etc/ssl/cert_ecdsa_prime256v1.crt --x509keyfile=/etc/ssl/key_ecdsa_prime256v1.pem" ""
}


# OpenSSL v1.0.2, TLSv1.2 with sect163k1 curve only.
function run_test_16 {
    run_test $1 '16' "/openssl_v1.0.2/openssl s_server -accept 443 -tls1_2 -named_curve sect163k1 -cert /etc/ssl/cert_1024.crt -key /etc/ssl/key_1024.pem" ""
}


# OpenSSL v1.1.1, TLSv1.2 with brainpoolP512r1 curve only.
function run_test_17 {
    run_test $1 '17' "/openssl_v1.1.1/openssl s_server -accept 443 -tls1_2 -named_curve brainpoolP512r1 -cert /etc/ssl/cert_1024.crt -key /etc/ssl/key_1024.pem" ""
}


# TLSv1.2 with ECDSA-SHA1 signature only.
function run_test_18 {
    run_test $1 '18' "/gnutls-3.6.11.1/gnutls-serv -p 443 --x509certfile=/etc/ssl/cert_ecdsa_prime256v1.crt --x509keyfile=/etc/ssl/key_ecdsa_prime256v1.pem --priority=NONE:-VERS-TLS1.0:-VERS-TLS1.1:+VERS-TLS1.2:-VERS-TLS1.3:+MAC-ALL:+GROUP-ALL:+SIGN-ECDSA-SHA1:+COMP-NULL:+CTYPE-SRV-ALL:+KX-ALL:+CHACHA20-POLY1305:+CAMELLIA-128-GCM:+AES-128-GCM" ""
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

    # Wait 250ms to ensure that the services in the container are fully initialized.
    sleep 0.25

    # Run sslscan and cut out the first two lines.  Those contain the version number
    # and local version of OpenSSL, which can change over time (and when they do, this
    # would break the test if they were left in).
    ./sslscan $sslscan_additional_args 127.0.0.1:4443 | tail -n +3 > $test_result_stdout
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
	all_passed=0
	return
    fi

    # Compare the actual output to the expected output.  Any discrepency results in test failure.
    diff=`diff -u ${expected_result_stdout} ${test_result_stdout}`
    if [[ $? != 0 ]]; then
	echo -e "Test #${test_number} ${REDB}FAILED${CLR}.\n\n${diff}\n"
	all_passed=0
	return
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

is_debian=0
is_arch=0

# If dpkg exists, assume this is a Debian-based system.
dpkg --version > /dev/null 2>&1
if [[ $? == 0 ]]; then
    is_debian=1
fi

# If pacman exists, assume this is an Arch system.
pacman --version > /dev/null 2>&1
if [[ ($is_debian == 0) && ($? == 0) ]]; then
    is_arch=1
fi

# Ensure that the libgmp-dev, m4, and wget packages are installed.  Use dpkg on Debian, or pacman on Arch.
if [[ $is_debian == 1 ]]; then
    dpkg -l libgmp-dev m4 perl wget > /dev/null 2>&1
    if [[ $? != 0 ]]; then
        echo -e "${REDB}Error: libgmp-dev, m4, perl and/or wget packages not installed.  Fix with: apt install libgmp-dev m4 perl wget${CLR}"
        exit 1
    fi
elif [[ $is_arch == 1 ]]; then
    pacman -Qi gmp m4 perl wget > /dev/null 2>&1
    if [[ $? != 0 ]]; then
        echo -e "${REDB}Error: gmp, m4, perl and/or wget packages not installed.  Fix with: pacman -S gmp m4 perl wget${CLR}"
        exit 1
    fi
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

if [[ $all_passed == 1 ]]; then
    echo -e "\n${GREENB}ALL TESTS PASS!${CLR}\n"
    rm -rf $TEST_RESULT_DIR
    exit 0
else
    echo -e "\n\n${YELLOWB}!! SOME TESTS FAILED !!${CLR}\n\n"
    exit 1
fi
