# Copyright (c) 2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import lxml.etree
from copy import deepcopy
from pkg_resources import resource_stream  # pylint: disable-msg=E0611
import re

import six
from six.moves.urllib.parse import quote_plus
from functools import partial
from xml.sax import saxutils

from swift.common.utils import get_logger
from swift.common.middleware.s3api.exception import S3Exception
from swift.common.middleware.s3api.utils import camel_to_snake, \
    utf8encode, utf8decode

XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8"?>\n'
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'
XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

_VALID_XML_CHAR_REGEXP = re.compile(  # ordered by presumed frequency
    '[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]')
_FAKE_TEXT_REGEX = re.compile(b'fake ([0-9]+) text')


class XMLSyntaxError(S3Exception):
    pass


class DocumentInvalid(S3Exception):
    pass


def cleanup_namespaces(elem):
    def remove_ns(tag, ns):
        if tag.startswith('{%s}' % ns):
            tag = tag[len('{%s}' % ns):]
        return tag

    if not isinstance(elem.tag, six.string_types):
        # elem is a comment element.
        return

    # remove s3 namespace
    elem.tag = remove_ns(elem.tag, XMLNS_S3)

    # remove default namespace
    if elem.nsmap and None in elem.nsmap:
        elem.tag = remove_ns(elem.tag, elem.nsmap[None])

    for e in elem.iterchildren():
        cleanup_namespaces(e)


def fromstring(text, root_tag=None, logger=None):
    try:
        elem = lxml.etree.fromstring(text, parser)
    except lxml.etree.XMLSyntaxError as e:
        if logger:
            logger.debug(e)
        raise XMLSyntaxError(e)

    cleanup_namespaces(elem)

    if root_tag is not None:
        # validate XML
        try:
            path = 'schema/%s.rng' % camel_to_snake(root_tag)
            with resource_stream(__name__, path) as rng:
                lxml.etree.RelaxNG(file=rng).assertValid(elem)
        except IOError as e:
            # Probably, the schema file doesn't exist.
            logger = logger or get_logger({}, log_route='s3api')
            logger.error(e)
            raise
        except lxml.etree.DocumentInvalid as e:
            if logger:
                logger.debug(e)
            raise DocumentInvalid(e)

    return elem


def tostring(tree, use_s3ns=True, xml_declaration=True):
    if use_s3ns:
        nsmap = tree.nsmap.copy()
        nsmap[None] = XMLNS_S3

        root = Element(tree.tag, attrib=tree.attrib, nsmap=nsmap)
        root.text = tree.text
        root.extend(deepcopy(list(tree)))
        tree = root

    return lxml.etree.tostring(tree, xml_declaration=xml_declaration,
                               encoding='UTF-8')


class _Element(lxml.etree.ElementBase):
    """
    Wrapper Element class of lxml.etree.Element to support
    a utf-8 encoded non-ascii string as a text.

    Why we need this?:
    Original lxml.etree.Element supports only unicode for the text.
    It declines maintainability because we have to call a lot of encode/decode
    methods to apply account/container/object name (i.e. PATH_INFO) to each
    Element instance. When using this class, we can remove such a redundant
    codes from swift.common.middleware.s3api middleware.
    """
    def __init__(self, *args, **kwargs):
        # pylint: disable-msg=E1002
        super(_Element, self).__init__(*args, **kwargs)

    @property
    def text(self):
        """
        utf-8 wrapper property of lxml.etree.Element.text
        """
        if six.PY2:
            return utf8encode(lxml.etree.ElementBase.text.__get__(self))
        return lxml.etree.ElementBase.text.__get__(self)

    @text.setter
    def text(self, value):
        lxml.etree.ElementBase.text.__set__(self, utf8decode(value))


parser_lookup = lxml.etree.ElementDefaultClassLookup(element=_Element)
parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
parser.set_element_class_lookup(parser_lookup)

Element = parser.makeelement
SubElement = lxml.etree.SubElement


def init_xml_texts(url_encoding=False):
    """
    Return
    - a function to correctly escape all the texts contained in the XML:
      this function must be used on all the texts coming from the client
    - a function to build the final version of the XML

    When the response is not URL-encoded, reference characters must be used
    for non valid XML characters.
    But the 'lxml' module does not support these non valid XML characters.
    The trick is therefore to put a fake text which is replaced at the end
    by the real text correctly escaped.
    """
    if url_encoding:
        to_be_escaped_later = None
    else:
        to_be_escaped_later = []
    escape_xml_text = partial(_escape_xml_text, to_be_escaped_later)
    finalize_xml_texts = partial(_finalize_xml_texts, to_be_escaped_later)
    return escape_xml_text, finalize_xml_texts


def _escape_xml_text(to_be_escaped_later, text):
    if not text:
        return text
    if to_be_escaped_later is None:
        return quote_plus(text.encode("utf-8"), safe="/")
    i = len(to_be_escaped_later)
    to_be_escaped_later.append(text)
    # Use spaces so as not to confuse with an ID or an urlencoded string
    # or a bucket name
    return f'fake {i} text'


def _finalize_xml_texts(to_be_escaped_later, body):
    if not to_be_escaped_later:
        return body
    # Replace with the real text correctly escaped
    return re.sub(
        _FAKE_TEXT_REGEX,
        partial(_replace_fake_text, to_be_escaped_later),
        body)


def _replace_fake_text(to_be_escaped_later, m):
    i = int(m.group(1))
    escaped_name = saxutils.escape(to_be_escaped_later[i])
    return re.sub(_VALID_XML_CHAR_REGEXP, _char_to_char_reference,
                  escaped_name).encode('utf-8')


def _char_to_char_reference(m):
    return '&#x%x;' % ord(m.group(0))
