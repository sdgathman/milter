VERS=milter-1.0
TAG=$(VERS)
SRCTAR=$(VERS).tar.gz

tar:
	git archive --format=tar.gz --prefix=$(VERS)/ -o $(SRCTAR) $(TAG)
