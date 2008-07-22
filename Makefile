client:
	cd switzerland/client ; $(MAKE) FastCollector

BASE=/usr/local
PYVER=python2.5
MODULEDEST=$(BASE)/lib/$(PYVER)/site-packages/switzerland

# This is a bit crazy.  Maybe someone with automake skillz will save us

# It's not clear why we bother making FastCollector and switzerland-client
# world executable, since currently only root can run them.

install: client
	# Make the directories for all our Python modules
	test -d $(MODULEDEST) || mkdir -p $(MODULEDEST)
	test -d $(MODULEDEST)/server || mkdir $(MODULEDEST)/server
	chmod 755 $(MODULEDEST)/server
	test -d $(MODULEDEST)/client || mkdir $(MODULEDEST)/client
	chmod 755 $(MODULEDEST)/client
	test -d $(MODULEDEST)/common || mkdir $(MODULEDEST)/common
	chmod 755 $(MODULEDEST)/common
	test -d $(MODULEDEST)/lib || mkdir $(MODULEDEST)/lib
	chmod 755 $(MODULEDEST)/lib
	# Put the modules there
	cp switzerland/__init__.py $(MODULEDEST)/
	chmod 644 $(MODULEDEST)/__init__.py
	cp switzerland/server/*.py $(MODULEDEST)/server
	cp switzerland/client/*.py $(MODULEDEST)/client
	cp switzerland/common/*.py $(MODULEDEST)/common
	cp switzerland/lib/*.py $(MODULEDEST)/lib
	chmod 644 $(MODULEDEST)/*/*
	# There are three executables in Switzerland.  The user should never run
	# FastCollector, so really it should live in a lib directory, but that will
	# reqiure PacketListener.py to know what that directory is...
	cp switzerland/client/FastCollector $(BASE)/bin/
	chmod 755 $(BASE)/bin/FastCollector
	cp switzerland-client $(BASE)/bin/ 
	chmod 755 $(BASE)/bin/switzerland-client
	cp switzerland-server $(BASE)/bin/
	chmod 755 $(BASE)/bin/switzerland-server
	
