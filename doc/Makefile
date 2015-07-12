# Make rules for www.python.org ht->html generation.  SOURCES
# indirection filters out "*.ht" value when no ht files are around.
SOURCES =	$(shell echo *.ht)
TARGETS =	$(filter-out *.html,$(SOURCES:%.ht=%.html)) $(EXTRA_TARGETS)
GENERATED_HTML= $(SOURCES:.ht=.html)

HTROOT = 	.
HT2HTML =	/usr/share/ht2html/ht2html.py
HTSTYLE =	MilterGenerator
HTALLFLAGS =	-f -s $(HTSTYLE)
HTFLAGS =	$(HTALLFLAGS) -r $(HTROOT)

DEST = 		spidey:/Public/python
EXCLUDES =	--exclude CVS
ARGS = 		--rsh=ssh -v -r -l -t --update --delete $(EXCLUDES)

.SUFFIXES:	.ht .html

.ht.html:
	$(HT2HTML) $(HTFLAGS) $<

all: $(TARGETS)

$(TARGETS): links.h

clean:
	-rm -f *~
	-rm $(GENERATED_HTML)

install: all
	rsync $(ARGS) *.html *.gif art/*.* $(DEST)
	mv milter.html index.html
	cp ../milter.cfg .
	zip doc HOWTO *.cfg *.html *.gif *.asc art/*.*
