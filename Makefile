#
# Makefile : Builds vscpl2drv-tcpiplink.so for Unix.
#

# Package version
MAJOR_VERSION=1
MINOR_VERSION=1
RELEASE_VERSION=0
BUILD_VERSION=0
PACKAGE_VERSION=1.1.0

STATIC=no
VSCP_PROJ_BASE_DIR=/var/lib/vscp/
DESTDIR=/var/lib/vscp/

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_DIR = /usr/bin/install -c -d
PROJ_SUBDIRS=linux 
VSCP_PROJ_BASE_DIR=/var/lib/vscp/
IPADDRESS :=  $(shell hostname -I)


all:
	@for d in $(PROJ_SUBDIRS); do (echo "====================================================" &&\
	echo "Building in dir " $$d && echo "====================================================" && cd $$d && $(MAKE)); done


install: 
	$(INSTALL_DIR) $(DESTDIR)/vscpd 
	$(INSTALL_PROGRAM) install-files/vscpl2drv-tcpiplink.conf $(DESTDIR)/vscpd
# Install sub components
	@for d in $(PROJ_SUBDIRS); do (echo "====================================================" &&\
	echo "Building in dir " $$d && echo "====================================================" && cd $$d && $(MAKE) install); done

uninstall: 
	rm $(DESTDIR)/vscpd/vscpl2drv-tcpiplink.conf
# Uninstall sub components
	@for d in $(PROJ_SUBDIRS); do (echo "====================================================" &&\
	echo "Building in dir " $$d && echo "====================================================" && cd $$d && $(MAKE) uninstall); done

man:
# create manual pages
	@for d in $(PROJ_SUBDIRS); do (cd $$d && $(MAKE) clean); done

clean: 
	@for d in $(PROJ_SUBDIRS); do (cd $$d && $(MAKE) clean); done
	rm -f config.log
	rm -f config.startup
	rm -f config.status

distclean: clean
	@sh clean_for_dist
