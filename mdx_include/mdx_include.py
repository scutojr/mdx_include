# -*- coding: utf-8 -*-
'''
Include Extension for Python-Markdown
===========================================

Includes local or remote files

See <https://github.com/neurobin/mdx_include> for documentation.

Copyright Md. Jahidul Hamid <jahidulhamid@yahoo.com>

License: [BSD](http://www.opensource.org/licenses/bsd-license.php)

'''
from __future__ import absolute_import
from __future__ import unicode_literals
import markdown
import re
import os
from codecs import open
import pkgutil
import encodings
import logging
try:
    # python 3
    from urllib.parse import urlparse
    from urllib.parse import urlunparse
    from urllib.request import build_opener
    from urllib.request import HTTPRedirectHandler
except ImportError:
    # python 2
    from urlparse import urlparse
    from urlparse import urlunparse
    from urllib2 import HTTPRedirectHandler
    from urllib2 import build_opener
from . import version

__version__ = version.__version__

INCLUDE_SYNTAX_RE = re.compile(r'(?P<escape>\\)?\{!\s*(?P<path>.+?)\s*(\|\s*(?P<encoding>.+?)\s*)?!\}')

logging.basicConfig()
LOGGER_NAME = 'mdx_include-' + __version__
log = logging.getLogger(LOGGER_NAME)

def encoding_exists(encoding):
    """Check if an encoding is available in Python"""
    false_positives = set(["aliases"])
    found = set(name for imp, name, ispkg in pkgutil.iter_modules(encodings.__path__) if not ispkg)
    found.difference_update(false_positives)
    if encoding:
        if encoding in found:
            return True
        elif encoding.replace('-', '_') in found:
            return True
    return False

def get_remote_content(url, encoding='utf-8'):
    """Follow redirect and return the content"""
    try:
        log.info("Downloading url: "+ url)
        return build_opener(HTTPRedirectHandler).open(url).read().decode(encoding), True
    except Exception as err:
        # catching all exception, this will effectively return empty string
        log.exception("E: Failed to download: " + url)
        return '', False

class IncludeExtension(markdown.Extension):
    """Include Extension class for markdown"""

    def __init__(self,  *args, **kwargs):
        self.config = {
            'base_path': [ '.', 'Base path from where relative paths are calculated',],
            'encoding': [ 'utf-8', 'Encoding of the files.', ],
            'allow_local': [ True, 'Allow including local files.', ],
            'allow_remote': [ True, 'Allow including remote files.', ],
            'truncate_on_failure': [True, 'Truncate the include markdown if failed to get the content.'],
            }
        super(IncludeExtension, self).__init__(*args, **kwargs)

    def extendMarkdown(self, md, md_globals):
        md.preprocessors.add( 'mdx_include', IncludePreprocessor(md, self.config),'_begin')


class IncludePreprocessor(markdown.preprocessors.Preprocessor):
    '''
    This provides an "include" function for Markdown. The syntax is {! file_path | encoding !} or
    simply {! file_path !} for default encoding from config params. 
    file_path can be a remote URL.
    This is done prior to any other Markdown processing. 
    All file names are relative to the location from which Markdown is being called.
    '''
    def __init__(self, md, config):
        super(IncludePreprocessor, self).__init__(md)
        self.base_path = config['base_path'][0]
        self.encoding = config['encoding'][0]
        self.allow_local = config['allow_local'][0]
        self.allow_remote = config['allow_remote'][0]
        self.truncate_on_failure = config['truncate_on_failure'][0]


    def run(self, lines):
        i = -1
        for line in lines:
            i = i + 1
            ms = INCLUDE_SYNTAX_RE.finditer(line)
            resl = ''
            c = 0
            for m in ms:
                text = ''
                stat = True
                total_match = m.group(0)
                d = m.groupdict()
                escape = d.get('escape')
                if not escape:
                    filename = d.get('path')
                    filename = os.path.expanduser(filename)
                    encoding = d.get('encoding')
                    if not encoding_exists(encoding):
                        if encoding:
                            log.warning("W: Wrong encoding specified (%s). Falling back to: %s" % (encoding, self.encoding,))
                        encoding = self.encoding
                        
                    urlo = urlparse(filename)
                    
                    if self.allow_remote and urlo.netloc:
                        # remote url
                        filename = urlunparse(urlo)
                        text, stat = get_remote_content(filename, encoding)
                    elif self.allow_local:
                        # local file
                        if not os.path.isabs(filename):
                            filename = os.path.normpath(os.path.join(self.base_path, filename))
                        try:
                            with open(filename, 'r', encoding=encoding) as f:
                                text = f.read()
                        except Exception as e:
                            log.exception('E: Could not find file: {}'.format(filename,))
                            # Do not break or continue, think of current offset, it must be
                            # set to end offset after replacing the matched part
                            stat = False
                    else:
                        # If allow_remote and allow_local both is false, then status is false
                        # so that user still have the option to truncate or not, text is empty now.
                        stat = False
                else:
                    # this one is escaped, gobble up the escape backslash
                    text = total_match[1:]
                
                if not stat and not self.truncate_on_failure:
                    # get content failed and user wants to retain the include markdown
                    text = total_match
                s, e = m.span()
                resl = ''.join([resl, lines[i][c:s], text ])
                # set the current offset to the end offset of this match
                c = e
            # All replacements are done, copy the rest of the string
            resl = ''.join([resl, lines[i][c:]])
            lines[i] = resl
        return lines

def makeExtension(*args, **kwargs):  # pragma: no cover
    return IncludeExtension(*args, **kwargs)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
