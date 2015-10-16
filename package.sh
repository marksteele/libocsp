#!/bin/bash

PKG_REVISION=`git describe --tags`
PKG_VERSION=`git describe --tags | tr - .`
PKG_ID=ocsp-${PKG_VERSION}
PKG_BUILD=1
DISTRO="."
PKG_VERSION_NO_H=`echo ${PKG_VERSION} | tr - .`

mkdir -p package
rm -rf package/ocsp
git archive --format=tar --prefix=${PKG_ID}/ ${PKG_REVISION}| (cd package && tar -xf -)
find package/${PKG_ID} -depth -name ".git" -exec rm -rf {} \;
tar -C package -czf package/${PKG_ID}.tar.gz ${PKG_ID}
rm -rf package/${PKG_ID}

cd package
PWD=`pwd`
mkdir -p BUILD
mkdir -p packages
#rpmbuild --define "_rpmfilename ocsp-${PKG_REVISION}-${PKG_BUILD}.x86_64.rpm" \
rpmbuild --define "_topdir ${PWD}" \
    --define "_sourcedir ${PWD}" \
    --define "_specdir ${PWD}" \
    --define "_rpmdir ${PWD}/packages" \
    --define "_srcrpmdir ${PWD}/packages" \
    --define "_revision ${PKG_VERSION}" \
    --define "_version ${PKG_VERSION_NO_H}" \
    --define "_release ${PKG_BUILD}" \
    --define "_tarname ${PKG_ID}.tar.gz" \
    --define "_tarname_base ${PKG_ID}" \
    -ba ../specfile
cd packages && for rpmfile in *.rpm; do sha256sum ${rpmfile} > ${rpmfile}.sha; done
cd x86_64 && for rpmfile in *.rpm; do sha256sum ${rpmfile} > ${rpmfile}.sha; done
