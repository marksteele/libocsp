#!/bin/bash

if [ $# -ne 1 ]; then
  echo "You need to specify a tag"
  exit 1
fi
git add .
git commit -m "packaging"
git push
git tag -d v${1}
git push origin :refs/tags/v${1}
git tag -a v${1} -m "${1} release"
git push --tags

PKG_REVISION=`git describe --tags`
PKG_VERSION=`git describe --tags | tr - .`
PKG_ID=libocsp-${PKG_VERSION}
PKG_BUILD=1
DISTRO="."
PKG_VERSION_NO_H=`echo ${PKG_VERSION} | tr - .`

mkdir -p package
rm -rf package/libocsp
git archive --format=tar --prefix=${PKG_ID}/ ${PKG_REVISION}| (cd package && tar -xf -)
mkdir -p package/${PKG_ID}/priv
find package/${PKG_ID} -depth -name ".git" -exec rm -rf {} \;
tar -C package -czf package/${PKG_ID}.tar.gz ${PKG_ID}
exit

cd package
PWD = `pwd`
mkdir -p BUILD
mkdir -p packages
rpmbuild --define "_rpmfilename libocsp-${PKG_REVISION}-${PKG_BUILD}.x86_64.rpm" \
		--define "_topdir ${PWD}" \
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
