#!/usr/bin/env python

import keyring
import getpass
import ConfigParser
import tempfile,os,sys
import xattr
import iso8601
import calendar
from datetime import datetime
from onedrive.api_v5 import OneDriveAuth
import signal
import BaseHTTPServer
import functools as ft
import urllib
import urlparse
import json
import types
import lxml
import lxml.html
from lxml import etree
import mimetypes
import collections
from StringIO import StringIO
import string
import random

import sys

from optparse import OptionParser

global interrupted
interrupted = False

auth_code = None

class AuthenticationError(Exception):
    pass

class AuthHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        global auth_code
        global KEEP_RUNNING
        KEEP_RUNNING = False
        """Respond to a GET request."""
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write("<html><head><title>Authorization successful</title></head>")
        s.wfile.write("<body><p>Successfully authorized</p>")
        auth_code = s.path
        s.wfile.write("</body></html>")

def signal_handler(signal, frame):
        print >> sys.stderr, 'Onenote pipe: Aborting'
        interrupted = True
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def main():
    parser = OptionParser()
    parser.add_option("-c", "--command", dest="command",
                      help="run COMMAND", metavar="COMMAND")
    parser.add_option("-n", "--notebook", dest="notebook",
                      help="Specify notebook")
    parser.add_option("-s", "--section", dest="section", help="Specify section")
    parser.add_option("-f", "--filename", dest="filename", help="HTML file to read")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    (options, args) = parser.parse_args()
    global verbose
    verbose = options.verbose

    client = get_client()
    if options.command == "login":
        print client.auth_access_token
    if options.command == "notebooks":
        get_notebooks(client)
    if options.command == "sections" :
        get_sections(client,options.notebook)
    if options.command == "upload" :
        write_page(client,options.notebook,options.section,options.filename)

def get_notebooks(client):
    datas = client.do_request(url='notebooks', query={'select' : 'name'})['value']
    notebooknames = [ notebook['name'] for notebook in datas]
    print "\n".join(notebooknames)

def get_sections(client,notebook_name):
    datas = client.do_request(url='notebooks', query={'filter' : "name eq \'%s\'" % notebook_name, 'select' : "id" })['value']
    if datas:
        datas = client.do_request(url='notebooks/%s/sections' % datas[0]['id'], query={'select' : 'name'} )['value']
        sectionnames = [ section['name'] for section in datas]
        print  "\n".join(sectionnames)

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def read_html(filename):
    parser = etree.HTMLParser()
    tree = etree.parse(open(filename),parser)
    elements_to_read = tree.xpath('//img[not(starts-with(@src, "http"))]') + tree.xpath('//object[starts-with(@data, "file://")]')
    to_attach = []
    if not elements_to_read:
        return(values,none)
    for external in elements_to_read:
        part_id = id_generator()
        filename = None
        if external.tag == 'img':
            filename = external.get('src')
            external.set('src','name:%s' % part_id)
        if external.tag == 'object':
            filename = external.get('data')
            external.set('data','name:%s' % part_id)
        to_attach.append( ( part_id, filename.replace('file://','') ) )
    files = collections.OrderedDict()
    files['Presentation'] = ('Presentation',StringIO('<?xml version="1.0" encoding="utf-8" ?>'+lxml.html.tostring(tree)),'application/xhtml+xml')
    for (part, attachment) in to_attach:
        (mimetype,encoding) = mimetypes.guess_type(attachment)
        files[part] = (attachment, open(attachment, 'rb'), mimetype)

    return ('<?xml version="1.0" encoding="utf-8" ?>'+lxml.html.tostring(tree),files)

def write_page(client,notebook_name,section_name,filename):
    (html,files) = read_html(filename)
    datas = client.do_request(url='notebooks', query={'filter' : "name eq \'%s\'" % notebook_name, 'select' : "id" })['value']
    if datas:
        notebook_id = datas[0]['id']
        datas = client.do_request(url='notebooks/%s/sections' % notebook_id, query={'select' : 'id'} )['value']
        if datas:
            section_id = datas[0]['id']
    if notebook_id and section_id:
        if (files):
            print "Sending file attachments"
            datas = client.do_request('sections/%s/pages' % section_id, method='post', files=files )
        else:
            datas = client.do_request('sections/%s/pages' % section_id,data = html, method='post', headers = { 'Content-Type': 'application/xhtml+xml' })
        print datas

class OneDrive(OneDriveAuth):

    api_url_base = 'https://www.onenote.com/api/v1.0/'

    def _api_url(self, path, query=dict(),
                 pass_access_token=True, pass_empty_values=False):
        query = query.copy()

        if pass_access_token:
            query.setdefault('access_token', self.auth_access_token)

        if not pass_empty_values:
            for k, v in query.viewitems():
                if not v and v != 0:
                    raise AuthenticationError(
                        'Empty key {!r} for API call (path: {})'
                        .format(k, path))

        return urlparse.urljoin(self.api_url_base,
                                '{}?{}'.format(path, urllib.urlencode(query)))

    def do_request(self, url='notebooks', query=dict(), query_filter=True, auth_header=True, auto_refresh_token=True, **request_kwz):
        """Make an arbitrary call to LiveConnect API.
            Shouldn't be used directly under most circumstances."""
        if query_filter:
            query = dict((k, v) for k, v in
                         query.viewitems() if v is not None)
        if auth_header:
            request_kwz.setdefault('headers', dict())['Authorization'] = (
                'Bearer {}'.format(self.auth_access_token))

        kwz = request_kwz.copy()
        kwz.setdefault('raise_for', dict())[401] = AuthenticationError
        api_url = ft.partial(self._api_url,
                             url, query, pass_access_token=not auth_header)
        try:
            return self.request(api_url(), **kwz)

        except AuthenticationError:
            if not auto_refresh_token:
                raise
            self.auth_get_token()
            if auth_header:  # update auth header with a new token
                request_kwz['headers']['Authorization'] \
                    = 'Bearer {}'.format(self.auth_access_token)
            return self.request(api_url(), **request_kwz)


def get_client(force=False):
    global auth_code
    global KEEP_RUNNING

    config_file = 'onenote.cfg'
    config = ConfigParser.SafeConfigParser({
                'client_id':'',
                'client_secret':''
                })
    config.read( [ config_file, os.path.expanduser('~/.onenote.cfg') ])
    if not config.has_section('onenote'):
        config.add_section('onenote')

    client_id = config.get('onenote','client_id')
    client_secret = config.get('onenote','client_secret')

    client = OneDrive(client_id=client_id,client_secret=client_secret,auth_redirect_uri='http://ronenote.localtest.me:8000', auth_scope=('office.onenote_create','office.onenote_update','wl.offline_access'))

    refresh_token = keyring.get_password('onenote','refresh_token')

    if force or refresh_token is None:
        print >> sys.stderr, "Performing a new login"

        print client.auth_user_get_url()
        server_class = BaseHTTPServer.HTTPServer
        httpd = server_class(('', 8000), AuthHandler)
        KEEP_RUNNING = True

        def keep_running():
            global KEEP_RUNNING
            return KEEP_RUNNING
        try:
            while keep_running():
                httpd.handle_request()
        except KeyboardInterrupt:
            pass

        httpd.server_close()
        client.auth_user_process_url(auth_code)
    else:
        client.auth_refresh_token = refresh_token
    try:
        client.auth_get_token()
    except:
        return get_client(True)

    keyring.set_password('onenote', 'refresh_token', client.auth_refresh_token)


    # Spit back a username/client combo
    return client


if __name__ == "__main__":
    main()

