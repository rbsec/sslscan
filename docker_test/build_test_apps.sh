#!/bin/bash

#
# Copyright (C) 2019-2025  Joe Testa <jtesta@positronsecurity.com>
#
# This script, designed to run inside a container, will build several versions of OpenSSL and GnuTLS so that testing can be done against them.
#


# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
REDB="\033[1;31m"    # Red + bold
YELLOWB="\033[1;33m" # Yellow + bold
GREENB="\033[1;32m"  # Green + bold


# Number of processors on this system (used to compile parallel builds).
NUM_PROCS=$(/usr/bin/nproc --all)
if [[ "${NUM_PROCS}" == "" ]]; then
    NUM_PROCS=4
fi


# Compile all version of GnuTLS.
function compile_gnutls_all {
    compile_gnutls '3.6.11.1'
    compile_gnutls '3.8.9'
}


# Compile all versions of Mbed TLS.
function compile_mbedtls_all {
    compile_mbedtls '3.6.3.1'
}


# Compile all versions of OpenSSL.
function compile_openssl_all {
    compile_openssl '1.0.0'
    compile_openssl '1.0.2'
    compile_openssl '1.1.1'
    compile_openssl '3.5.0'
}


# Compile a specific version of Mbed TLS (https://github.com/Mbed-TLS/mbedtls).
function compile_mbedtls {
    version=$1

    git_tag=
    output_dir=
    if [[ $version == '3.6.3.1' ]]; then
	git_tag="v3.6.3.1"
        output_dir="mbedtls_v3.6.3.1_dir"
    else
	echo -e "${REDB}Error: Mbed TLS v${version} is unknown!${CLR}"
	exit 1
    fi

    echo -e "\n${YELLOWB}Downloading Mbed TLS v${version}...${CLR}\n"
    git clone --depth 1 -b ${git_tag} https://github.com/Mbed-TLS/mbedtls ${output_dir}

    echo -e "\n${YELLOWB}Compiling Mbed TLS v${version}...${CLR}\n"
    pushd ${output_dir}

    # Install Python module dependencies for build system.
    python3 -m venv venv
    source venv/bin/activate  # Required, otherwise pip fails to install anything.
    python3 -m pip install -r scripts/basic.requirements.txt

    # Now compile it.
    make -j ${NUM_PROCS}

    if [[ ! -f programs/ssl/ssl_server2 ]]; then
        echo -e "${REDB}Error: compilation failed!  ssl_server2 not found.${CLR}"
        exit 1
    fi

    # Copy the ssl_server2 program to the build directory.
    cp "programs/ssl/ssl_server2" "/build/mbedtls_ssl_server2_v${version}"

    popd

    # Delete the source code directory now that we built the 'openssl' tool and moved it out.
    rm -rf ${output_dir}
    echo -e "\n\n${YELLOWB}Compilation of Mbed TLS v${version} finished.${CLR}\n\n"
}


# Compile a specific version of OpenSSL.
function compile_openssl {
    version=$1

    git_tag=
    compile_args=
    precompile_command=
    output_dir=
    compile_num_procs=${NUM_PROCS}
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
    elif [[ $version == '3.5.0' ]]; then
	git_tag="openssl-3.5.0"
	compile_args="enable-weak-ssl-ciphers no-shared zlib"
	output_dir="openssl_v3.5.0_dir"
    else
	echo -e "${REDB}Error: OpenSSL v${version} is unknown!${CLR}"
	exit 1
    fi

    # Download OpenSSL from github.
    echo -e "\n${YELLOWB}Downloading OpenSSL v${version}...${CLR}\n"
    git clone --depth 1 -b ${git_tag} https://github.com/openssl/openssl/ ${output_dir}

    # Configure and compile it.
    echo -e "\n\n${YELLOWB}Compiling OpenSSL v${version} with \"-j ${compile_num_procs}\"...${CLR}"
    pushd ${output_dir}
    ./config ${compile_args}
    if [[ ${precompile_command} != '' ]]; then ${precompile_command}; fi
    make -j ${compile_num_procs}

    # Ensure that the 'openssl' command-line tool was built.
    if [[ ! -f "apps/openssl" ]]; then
	echo -e "${REDB}Error: compilation failed!  apps/openssl not found.${CLR}\n\nStrangely, sometimes OpenSSL v1.0.0 fails for no reason; simply running this script again and changing nothing fixes the problem.\n\n"
	exit 1
    fi

    # Copy the 'openssl' app to the top-level docker building dir as, e.g. 'openssl_prog_v1.0.0'.  Then we can delete the source code directory and move on.
    cp "apps/openssl" "/build/openssl_prog_v${version}"
    popd

    # Delete the source code directory now that we built the 'openssl' tool and moved it out.
    rm -rf ${output_dir}
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
    compile_num_procs=${NUM_PROCS}
    compile_nettle=0
    if [[ "${gnutls_version}" == "3.6.11.1" ]]; then
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
    elif [[ "${gnutls_version}" == "3.8.9" ]]; then
        echo "Using platform's nettle library."
        gnutls_url=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.9.tar.xz
	gnutls_expected_sha256=69e113d802d1670c4d5ac1b99040b1f2d5c7c05daec5003813c049b5184820ed
	gnutls_filename=gnutls-3.8.9.tar.xz
	gnutls_source_dir=gnutls-3.8.9
    else
	echo -e "${REDB}Error: GnuTLS v${gnutls_version} is unknown!${CLR}"
	exit 1
    fi

    # Download GnuTLS.
    echo -e "\n${YELLOWB}Downloading GnuTLS v${gnutls_version}...${CLR}\n"
    wget ${gnutls_url}

    # Check the SHA256 hash.
    gnutls_actual_sha256=$(sha256sum ${gnutls_filename} | cut -f1 -d" ")

    if [[ "${gnutls_actual_sha256}" != "${gnutls_expected_sha256}" ]]; then
        echo -e "${REDB}GnuTLS/nettle actual hashes differ from expected hashes! ${CLR}\n"
        echo -e "\tGnuTLS expected hash: ${gnutls_expected_sha256}\n"
        echo -e "\tGnuTLS actual hash:   ${gnutls_actual_sha256}\n"

        exit 1
    fi

    echo -e "${GREEN}GnuTLS hash verified.${CLR}\n"

    # Uncompress the archive.
    tar xJf ${gnutls_filename}

    # Some versions require us to compile a version of nettle ourselves.  For others, the system package version works perfectly.
    if [[ "${compile_nettle}" == 1 ]]; then

        # Download nettle.
        echo -e "\n${YELLOWB}Downloading nettle library v${nettle_version}...${CLR}\n"
        wget ${nettle_url}

        # Ensure the hash of the package is what we expect.
        nettle_actual_sha256=$(sha256sum ${nettle_filename} | cut -f1 -d" ")
        if [[ "${nettle_actual_sha256}" != "${nettle_expected_sha256}" ]]; then
            echo -e "${REDB}nettle actual hashes differ from expected hashes! ${CLR}\n"
            echo -e "\tnettle expected hash: ${nettle_expected_sha256}\n"
            echo -e "\tnettle actual hash:   ${nettle_actual_sha256}\n\n"
            exit 1
        fi

        echo -e "${GREEN}Nettle hash verified.${CLR}\n"

        tar xzf ${nettle_filename}
        mv ${nettle_source_dir} nettle

        # Configure and compile nettle.
        echo -e "\n\n${YELLOWB}Compiling nettle v${nettle_version} with \"-j ${compile_num_procs}\"...${CLR}"
        pushd nettle
        ./configure && make -j ${compile_num_procs} CFLAGS="-fPIC"

        if [[ ! -f libnettle.so || ! -f libhogweed.so ]]; then
            echo -e "${REDB}Error: compilation failed!  libnettle.so and/or libhogweed.so not found.${CLR}"
            exit 1
        fi
        popd
    fi

    # Configure and compile GnuTLS.
    echo -e "\n\n${YELLOWB}Compiling GnuTLS v${gnutls_version} with \"-j ${compile_num_procs}\"...${CLR}"
    pushd ${gnutls_source_dir}

    # This seems to be an existing system file which disables support for TLSv1.0 and v1.1!
    rm -f /etc/gnutls/config

    if [[ "${compile_nettle}" == 1 ]]; then
        nettle_source_dir_abs=$(readlink -f ../nettle)
        nettle_parent_dir=$(readlink -f ..)
        NETTLE_CFLAGS=-I${nettle_parent_dir} NETTLE_LIBS="-L${nettle_source_dir_abs} -lnettle" HOGWEED_CFLAGS=-I${nettle_parent_dir} HOGWEED_LIBS="-L${nettle_source_dir_abs} -lhogweed" ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-guile

        make CFLAGS="-static -fPIC -I${nettle_parent_dir}" LDFLAGS="-L${nettle_source_dir_abs} -lhogweed -lnettle" -j ${compile_num_procs}
    else
        ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit
        make CFLAGS="-static -fPIC" -j ${compile_num_procs}
    fi

    # Ensure that the gnutls-serv and gnutls-cli tools were built
    if [ ! -f "src/gnutls-cli" ] || [ ! -f "src/gnutls-serv" ]; then
	echo -e "${REDB}Error: compilation failed!  gnutls-cli and/or gnutls-serv not found.${CLR}\n"
	exit 1
    fi

    # Copy the gnutls-cli and gnutls-serv apps to the top-level docker building dir as, e.g. 'gnutls-cli-v3.6.11.1'.  Then we can delete the source code directory and move on.
    cp "src/gnutls-cli" "/build/gnutls-cli-v${gnutls_version}"
    cp "src/gnutls-serv" "/build/gnutls-serv-v${gnutls_version}"

    if [[ "${compile_nettle}" == 1 ]]; then
        cp "${nettle_source_dir_abs}/libhogweed.so" "/build/libhogweed.so.5"
        cp "${nettle_source_dir_abs}/libnettle.so" "/build/libnettle.so.7"
    fi
    popd

    # Delete the source code directory now that we built the tools and moved them out.
    rm -rf ${gnutls_source_dir}
    echo -e "\n\n${YELLOWB}Compilation of GnuTLS v${gnutls_version} finished.${CLR}\n\n"
}


echo -e "\n\nBuilding with ${GREENB}${NUM_PROCS}${CLR} threads.\n"

cd /build
compile_openssl_all
compile_gnutls_all
compile_mbedtls_all

# Strip all the programs of debugging symbols in order to cut down on storage space.
strip /build/openssl_prog*
strip /build/gnutls-cli*
strip /build/gnutls-serv*
strip /build/lib*
strip /build/mbedtls*

echo -e "\n\n${GREENB}Done compiling applications!${CLR}\n"
