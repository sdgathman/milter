VERS=milter-0.8.17
V=milter-0_8_17

tar:
	cvs export -r $(V) -d $(VERS) milter
	tar cvf $(VERS).tar $(VERS)
	gzip -v $(VERS).tar
	rm -rf $(VERS)

tag:	
	cvs tag -F $(V)
