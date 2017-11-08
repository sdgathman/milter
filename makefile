VERS=milter-0.9
TAG=$(VERS)
SRCTAR=$(VERS).tar.gz

tar:
	git archive --format=tar.gz --prefix=$(VERS)/ -o $(SRCTAR) $(TAG)
