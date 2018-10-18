#!/bin/bash

#
# Script to build OpenSSL deb packages from source with SSLv2 support
# Built packages are automatically installed with dpkg
# Tested on Debian Squeeze and Kali 1.0.8
# The packages will probably get replaced next time you do a system upgrade
# To prevent this, hold the packages using the following command
#
# $ echo "openssl hold" | sudo dpkg --set-selections
#


# Clean up previous build
sudo rm -rf openssl
mkdir openssl
cd openssl

# Exit if any command fails
set -e

# Install dependencies
sudo apt-get update
sudo apt-get -y --no-upgrade install build-essential devscripts quilt
sudo apt-get -y build-dep openssl

# Get the source
apt-get source openssl
cd openssl-*

# Revert the patches
quilt pop -a

# Remove the 'ssltest_no_sslv2.patch' line
sed -i '/ssltest_no_sslv2.patch/d' debian/patches/series

# Remove the 'no-ssl2' build argument
sed -i 's/ no-ssl2//g' debian/rules

# Re-apply patches
quilt push -a

# Packaging stuff
dch -n 'Allow SSLv2'
dpkg-source --commit

# Build the packges (takes a while)
sudo debuild -uc -us

# Install the packages
cd ..
sudo dpkg -i *ssl*.deb
