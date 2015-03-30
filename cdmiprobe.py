#!/usr/bin/python

import argparse, re, random, signal
import requests, sys, os, json, socket

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.SSL import Error as SSLError

HEADER_CDMI_VERSION = {'X-CDMI-Specification-Version': '1.0.2'}
CDMI_CONTAINER = 'application/cdmi-container'
CDMI_CAPABILITIES = 'application/cdmi-capabilities'
CDMI_OBJECT = 'application/cdmi-object'
CDMI_QUEUE = 'application/cdmi-queue'

CONTAINER = '/container-probe'
DOBJECT = '/dataobject-probe'

DEFAULT_PORT = 443

def server_ok(serverarg, capath, timeout):
    server_ctx = Context(TLSv1_METHOD)
    server_ctx.load_verify_locations(None, capath)

    def verify_cb(conn, cert, errnum, depth, ok):
        return ok
    server_ctx.set_verify(VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)

    serverarg = re.split("/*", serverarg)[1]
    if ':' in serverarg:
        serverarg = serverarg.split(':')
        server = serverarg[0]
        port = int(serverarg[1])
    else:
        server = serverarg
        port = DEFAULT_PORT

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))

        server_conn = Connection(server_ctx, sock)
        server_conn.set_connect_state()

        try:
            def handler(signum, frame):
                raise socket.error('timeout after %s' % (timeout))

            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout)
            server_conn.do_handshake()
            signal.alarm(0)
        except socket.timeout as e:
            nagios_out('Critical', 'connection error %s - %s' % (serverarg, repr(e)), 2)

        server_conn.shutdown()
        server_conn.close()

    except(SSLError, socket.error) as e:
        nagios_out('Critical', 'connection error %s - %s' % (serverarg, repr(e)), 2)

    return True

def nagios_out(status, msg, retcode):
    sys.stdout.write(status+": "+msg+"\n")
    sys.exit(retcode)

def get_keystone_scoped_token(server, userca, capath, timeout):
    try:
        headers, token = {}, None
        headers.update(HEADER_CDMI_VERSION)
        headers.update({'Accept': '*/*'})
        response = requests.get(server, headers=headers, cert=userca, verify=False)
        if response.status_code == 400:
            response = requests.get(server, headers={}, cert=userca, verify=False)
    except requests.exceptions.ConnectionError as e:
        nagios_out('Critical', 'connection error %s - %s' % (server, str(e)), 2)

    try:
        keystone_server = re.search("Keystone.*=[\s'\"]*([\w:/\-_\.]*)[\s*\'\"]*", response.headers['www-authenticate']).group(1)
    except(KeyError, IndexError, AttributeError):
        nagios_out('Critical', 'could not fetch keystone server from response', 2)

    if server_ok(keystone_server, capath, timeout):
        try:
            token_suffix = ''
            if keystone_server.endswith("v2.0"):
                token_suffix = token_suffix+'/tokens'
            else:
                token_suffix = token_suffix+'/v2.0/tokens'

            headers, payload, token = {}, {}, None
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'Accept': '*/*'})

            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            payload = {'auth': {'voms': True}}
            response = requests.post(keystone_server+token_suffix, headers=headers,
                                    data=json.dumps(payload), cert=userca, verify=False)
            token = response.json()['access']['token']['id']
        except(KeyError, IndexError):
            nagios_out('Critical', 'could not fetch unscoped keystone token from response', 2)
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'connection error %s - %s' % (keystone_server+token_suffix, str(e)), 2)

        try:
            tenant_suffix= ''
            if keystone_server.endswith("v2.0"):
                tenant_suffix = tenant_suffix+'/tenants'
            else:
                tenant_suffix = tenant_suffix+'/v2.0/tenants'
            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            headers.update({'x-auth-token': token})
            response = requests.post(keystone_server+tenant_suffix, headers=headers,
                                    data=None, cert=userca, verify=False)
            response.raise_for_status()
            tenants = response.json()['tenants']
            tenant = ''
            for t in tenants:
                if 'ops' in t['name']:
                    tenant = t['name']
        except(KeyError, IndexError):
            nagios_out('Critical', 'could not fetch allowed tenants from response', 2)
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'connection error %s - %s' % (keystone_server+tenant_suffix, str(e)), 2)

        try:
            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            payload = {'auth': {'voms': True, 'tenantName': tenant}}
            response = requests.post(keystone_server+token_suffix, headers=headers,
                                    data=json.dumps(payload), cert=userca, verify=False)
            response.raise_for_status()
            token = response.json()['access']['token']['id']

        except(KeyError, IndexError):
            nagios_out('Critical', 'could not fetch scoped keystone token for %s from response' % tenant, 2)
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'connection error %s - %s' % (keystone_server+token_suffix, str(e)), 2)

        return token

def main():
    class ArgHolder(object):
        pass
    argholder = ArgHolder()

    argnotspec = []
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', dest='endpoint', nargs='?')
    parser.add_argument('--cert', dest='cert', nargs='?')
    parser.add_argument('-t', dest='timeout', type=int, nargs='?', default=120)
    parser.add_argument('--capath', dest='capath', nargs='?', default='/etc/grid-security/certificates')

    parser.parse_args(namespace=argholder)

    for arg in ['endpoint', 'cert', 'capath', 'timeout']:
        if eval('argholder.'+arg) == None:
            argnotspec.append(arg)

    if len(argnotspec) > 0:
        msg_error_args = ''
        for arg in argnotspec:
            msg_error_args += '%s ' % (arg)
        nagios_out('Unknown', 'command-line arguments not specified, '+msg_error_args, 3)
    else:
        if not argholder.endpoint.startswith("http") \
                or not os.path.isfile(argholder.cert) \
                or not type(argholder.timeout) == int \
                or not os.path.isdir(argholder.capath):
            nagios_out('Unknown', 'command-line arguments are not correct', 3)

    if server_ok(argholder.endpoint, argholder.capath, argholder.timeout):
        ks_token = get_keystone_scoped_token(argholder.endpoint,
                                    argholder.cert,
                                    argholder.capath,
                                    argholder.timeout)

        randstr = '-'+''.join(random.sample('abcdefghijklmno', 3))
        randdata = ''.join(random.sample('abcdefghij1234567890', 20))

        try:
            # create container
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'accept': CDMI_CONTAINER,
                            'content-type': CDMI_CONTAINER})
            headers.update({'x-auth-token': ks_token})
            response = requests.put(argholder.endpoint+CONTAINER+randstr+'/',
                                    headers=headers, cert=argholder.cert, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - create_container failed %s' % repr(e), 2)

        try:
            # create data object
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'accept': CDMI_OBJECT,
                            'content-type': CDMI_OBJECT})
            headers.update({'x-auth-token': ks_token})
            payload = {'mimetype': 'text/plain'}
            payload['value'] = unicode(randdata)
            payload['valuetransferencoding'] = 'utf-8'
            response = requests.put(argholder.endpoint+CONTAINER+randstr+DOBJECT+randstr,
                                    data=json.dumps(payload), headers=headers,
                                    cert=argholder.cert, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - create_dataobject failed %s' % repr(e), 2)

        try:
            # get data object
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'accept': CDMI_OBJECT,
                            'content-type': CDMI_OBJECT})
            headers.update({'x-auth-token': ks_token})
            response = requests.get(argholder.endpoint+CONTAINER+randstr+DOBJECT+randstr,
                                    headers=headers, cert=argholder.cert, verify=False)
            response.raise_for_status()
            if response.json()['value'] != randdata:
                raise requests.exceptions.HTTPError('data integrity violated')

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - get_dataobject failed %s' % repr(e), 2)

        newranddata = ''.join(random.sample('abcdefghij1234567890', 20))

        try:
            # update data object
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'accept': CDMI_OBJECT,
                            'content-type': CDMI_OBJECT})
            headers.update({'x-auth-token': ks_token})
            payload = {'mimetype': 'text/plain'}
            payload['value'] = unicode(newranddata)
            payload['valuetransferencoding'] = 'utf-8'
            response = requests.put(argholder.endpoint+CONTAINER+randstr+DOBJECT+randstr,
                                    data=json.dumps(payload), headers=headers,
                                    cert=argholder.cert, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - update_dataobject failed %s' % repr(e), 2)

        try:
            # get data object
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'accept': CDMI_OBJECT,
                            'content-type': CDMI_OBJECT})
            headers.update({'x-auth-token': ks_token})
            response = requests.get(argholder.endpoint+CONTAINER+randstr+DOBJECT+randstr,
                                    headers=headers, cert=argholder.cert, verify=False)
            response.raise_for_status()
            if response.json()['value'] != newranddata:
                raise requests.exceptions.HTTPError('data integrity violated')

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - get_dataobject failed %s' % repr(e), 2)

        try:
            # remove data object
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'x-auth-token': ks_token})
            response = requests.delete(argholder.endpoint+CONTAINER+randstr+DOBJECT+randstr,
                                    headers=headers, cert=argholder.cert, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - delete_dataobject failed %s' % repr(e), 2)

        try:
            # remove container
            headers, payload= {}, {}
            headers.update(HEADER_CDMI_VERSION)
            headers.update({'x-auth-token': ks_token})
            response = requests.delete(argholder.endpoint+CONTAINER+randstr+'/',
                                    headers=headers, cert=argholder.cert, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            nagios_out('Critical', 'test - delete_container failed %s' % repr(e), 2)

        nagios_out('OK', 'container and dataobject creating, fetching and removing tests were successful', 0)

main()
