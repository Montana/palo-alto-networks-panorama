#!/usr/bin/python3

import argparse
import logging
import os
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def api_call(ip, params, file):
    url = 'https://' + ip + '/api'
    files = {'file': open(file, 'rb')}

    r = requests.post(url, params=params, files=files, verify=False)

    if r.status_code == 200:
        return True
    else:
        return False


def import_certificate(ip, api_key, cert_name, cert_file):
    params = {
        'type': 'import',
        'category': 'certificate',
        'certificate-name': cert_name,
        'format': 'pem',
        'key': api_key
    }

    return api_call(ip, params, cert_file)


def import_private_key(ip, api_key, cert_name, privkey_file, privkey_pass):
    params = {
        'type': 'import',
        'category': 'private-key',
        'certificate-name': cert_name,
        'format': 'pem',
        'passphrase': privkey_pass,
        'key': api_key
    }

    return api_call(ip, params, privkey_file)


def commit(ip, api_key):
    url = 'https://' + ip + '/api'
    params = {'type': 'commit', 'cmd': '<commit></commit>', 'key': api_key}

    r = requests.get(url, params=params, verify=False)

    if r.status_code == 200:
        return True
    else:
        return False


def main():
    parser = argparse.ArgumentParser(
        description=
        '''Install Let's Encrypt certificate and private key on Palo Alto Networks 
        firewall or Panorama.
        ''')

    required_group = parser.add_argument_group('Palo Alto Networks Device')
    required_group.add_argument('target',
                                help='Hostname of firewall or Panorama.')
    required_group.add_argument('api_key',
                                help='API key to use for connection.')
    required_group.add_argument('cert_name',
                                help='Name to use for certificate.')
    required_group.add_argument('cert_file', help='Certificate file.')
    required_group.add_argument('privkey_file', help='Private key file.')
    required_group.add_argument('privkey_pass',
                                help='Password to decrypt private key.')

    args = parser.parse_args()
    logger = logging.basicConfig(format='%(message)s', level=logging.INFO)

    if import_certificate(args.target, args.api_key, args.cert_name,
                          args.cert_file):
        logging.info('Imported certificate OK.')
    else:
        logging.error('Error importing certificate.')
        sys.exit(-1)

    if import_private_key(args.target, args.api_key, args.cert_name,
                          args.privkey_file, args.privkey_pass):
        logging.info('Imported private key OK.')
    else:
        logging.error('Error importing private key.')
        sys.exit(-1)

    if commit(args.target, args.api_key):
        logging.info('Commited configuration.')
    else:
        logging.error('Error commiting configuration.')
        sys.exit(-1)


if __name__ == '__main__':
    main()
