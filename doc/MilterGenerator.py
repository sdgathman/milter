from StandardGenerator import StandardGenerator

class MilterGenerator(StandardGenerator):
    def __init__(self, file, rootdir, relthis):
      StandardGenerator.__init__(self,file,rootdir,relthis)

    def get_body_attributes(self): return ''
    def get_charset(self): return 'utf-8'
    def get_style(self):
        """Return the style sheet for this document"""
        return '''body { margin: 0px; }
DT              { font-weight: bolder; padding-top: 1em }'''
