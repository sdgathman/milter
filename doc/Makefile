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

#DEST = 		bmsi.com:/var/www/html/milter
DEST = 		h.pymilter.org:/var/www/html/milter
EXCLUDES =	--exclude .git
ARGS = 		-rav -l -t --update --delete $(EXCLUDES)

.SUFFIXES:	.ht .html

.ht.html:
	$(HT2HTML) $(HTFLAGS) $<

all: $(TARGETS)

$(TARGETS): links.h

clean:
	-rm -f *~
	-rm $(GENERATED_HTML)

install: all
	mv milter.html index.html
	rsync $(ARGS) *.html art $(DEST)
	cp ../milter.cfg .
	zip doc HOWTO *.cfg *.html *.asc art/*.*
