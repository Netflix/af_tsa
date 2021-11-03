KDIR = /lib/modules/`uname -r`/build
VERSION := $(shell git describe --tags)
export VERSION

.PHONY: kbuild
kbuild:
	make -C $(KDIR) M=`pwd`/src

.PHONY: clean
clean:
	make -C $(KDIR) M=`pwd`/src clean
	rm -r root

.PHONY:
fmt:
	clang-format -i src/*.c
	jsonnetfmt -i nfpm.jsonnet

.PHONY: package
package: tmp/dkms.conf tmp/nfpm.yaml tmp/postInstall.sh tmp/preRemove.sh
	mkdir -p build/
	nfpm package --packager deb --config tmp/nfpm.yaml --target build/taskintrospection_latest.deb

.PHONY: tmp/postInstall.sh
tmp/postInstall.sh: tmp
	mkdir -p tmp
	./mkpostInstall.sh > tmp/postInstall.sh
	chmod 755 tmp/postInstall.sh

.PHONY: tmp/preRemove.sh
tmp/preRemove.sh:
	mkdir -p tmp
	./mkpreRemove.sh > tmp/preRemove.sh
	chmod 755 tmp/preRemove.sh

.PHONY: tmp/nfpm.yaml
tmp/nfpm.yaml: nfpm.jsonnet
	jsonnet --ext-str version=$(VERSION) --ext-str srcdir=/usr/src/taskintrospection-${VERSION} -S nfpm.jsonnet > tmp/nfpm.yaml

.PHONY: tmp/dkms.conf
tmp/dkms.conf:
	mkdir -p tmp
	./mkdkms.sh > tmp/dkms.conf
