#!/usr/bin/env python2
###############################################################################
#
# Ansible VMware Inventory Application
#
# Retrieve Ansible formated inventory from one or more VMware servers.
#
# Retrieve VM listing of servers from one or more VMware servers and produce
# a list in Ansible JSON format.  Also retireve a list of VM properties, whcih
# can be dynamically set in an INI file as Host Variables.  Fianlly it can
# produce Ansible Groups based on the VMware properties as defined in the 
# INI file.
#
# The INI file default to the same base name as the Inventory Program and is
# expected in the same directory.  This can be orverridden by setting an
# environment variable (VMWARE_INI_PATH) to the location of the file.
#
# Changes:
#   20161223 - Added "--vms" parameter & code
#
# ToDo:
#    1) Cache data retrieve to avoid having to get it everytime
#    2) Support Aliases for the Ansible Group names which are properties based
# 
###############################################################################

import pysphere 
import re
import os
import sys
import argparse
import configparser
import base64
from stat import *
from Crypto.Cipher import AES


try:
    import json
except ImportError:
    import simplejson as json


###############################################################################
#
# Parse Command line arguments and update options
#
###############################################################################
def parse_args(options):

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='fqdn of vsphere server', action='store')
    parser.add_argument('-u', '--username', help='your vsphere username', action='store')
    parser.add_argument('-p', '--password', help='your vsphere password', action='store')
    parser.add_argument('-l', '--list', help='List all guest VMs', action='store_true')
    parser.add_argument('-g', '--host', help='Print a single guest', action='store')
    parser.add_argument('-n', '--no-ssl-verify', help="Do not do SSL Cert Validation", action='store_true')
    parser.add_argument('-v', '--vms', nargs='?', const='all', help='Single Column list of VMs', action='store')
    
    args = parser.parse_args()

    if args.no_ssl_verify is True:
        import ssl
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context

    if args.server:
        options['vmware']['servers'] = args.server

    if args.username:
        options['vmware']['username'] = args.username

    if args.password:
        options['vmware']['password'] = args.password

    if args.host:
        options['vmware']['node'] = args.host

    if args.vms:
        options['vmware']['vms'] = args.vms

    if not options['vmware']['password']:
        import getpass
        options['vmware']['password'] = getpass.getpass()

    return args



###############################################################################
#
# Parse INI file and update default otions
#
# If putting the password in the INI file use the following to encrypt it:
#      from Crypto.Cipher import AES
#      import base64
#      cipher = AES.new('VAULT_KEY'.rjust(32), AES.MODE_ECB)
#      base64.urlsafe_b64encode(cipher.encrypt('VMWARE-PASSWORD'.rjust(16)))
#
###############################################################################
def get_options():

    base_dir = __file__
    base_dir = os.path.basename(base_dir)
    base_dir = base_dir.replace('.py', '')

    defaults = { 'vmware' : {
        'servers': '',
        'port': 443,
        'username': '',
        'password': '',
        'cache': False,
        'cache_exp': 24,
        'groups': '',
        'properties': [ 'name', 'guest.hostName', 'guest.guestId', 'guest.guestState', 'config.hardware.numCPU', 'config.hardware.memoryMB' ],
        'ini_path': os.path.join(os.path.dirname(__file__), '%s.ini' % base_dir)
        }
    }

    ini_file = os.environ.get('VMWARE_INI_PATH', defaults['vmware']['ini_path'])
    ini_file = os.path.expanduser(os.path.expandvars(ini_file))
    config = configparser.ConfigParser()
    config.read(ini_file.decode("utf-8"))

    if config.has_section('vmware'):
        for k,v in config.items('vmware'):
            if k == "properties":
                for i in v.split(','):
                    if not i in defaults['vmware']['properties']:
                        defaults['vmware']['properties'].append(i)
            else:
                 defaults['vmware'][k] = v

    #
    # If the password is in the config file it is expected to have been encrypted
    #
    if defaults['vmware']['password'] != '':
        try:
            home_dir = os.path.expanduser('~')
            perms = oct(os.stat(home_dir + '/.ansible-vault.key')[ST_MODE])
            if perms[-3:] != '400' and perms[-3:] != '600':
                print "(Error): Key file permissions must be 400 or 600"
                sys.exit(1)

            with open( home_dir + '/.ansible-vault.key', 'r') as key_file:
                key = key_file.read().replace('\n','')
        except (OSError, IOError) as e:
            print("(Error): Password Unlock Key file [%s] not found" % (home_dir + '/.ansible-vault.key'))
            sys.exit(1)

        cipher = AES.new(key.rjust(32), AES.MODE_ECB)
        decode = cipher.decrypt(base64.urlsafe_b64decode(str(defaults['vmware']['password'])))
        defaults['vmware']['password'] = decode.strip()
        
    return defaults



###############################################################################
#
# Attempt to connect to vCenter
#
###############################################################################
def vcenter_connect(server_fqdn, server_username, server_password):
    vserver = pysphere.VIServer()
    try:
        vserver.connect(server_fqdn, server_username, server_password)
    except Exception as error:
        print(('Could not connect to vCenter: %s') % (error))
        sys.exit(1)

    return vserver



###############################################################################
#
# Ansible "--host" is not implemented as "_meta" is provided by "--list"
#
###############################################################################
def ansible_host(options, vms):
    print "{}"




###############################################################################
#
# Ansible "--list" returns JOSN vm listing
#
###############################################################################
def ansible_vms(options, vms):

    for server in vms:
        for vm in vms[server]:
            if 'hostname' in vms[server][vm]:
                vmname = vms[server][vm]['vmware_hostname']
            else:
                vmname = vms[server][vm]['vmware_name']

            if options['vmware']['vms'] == 'all':
                print vmname
            elif vmname.startswith(options['vmware']['vms']):
                print vmname


###############################################################################
#
# Ansible "--list" returns JOSN vm listing
#
###############################################################################
def ansible_list(options, vms):

    inventory ={}
    inventory["all_vms"] = {
        'hosts' : []
    }
    inventory['_meta'] = {
        'hostvars' : {}
    }

    for server in vms:
        for vm in vms[server]:
            if 'hostname' in vms[server][vm]:
                vmname = vms[server][vm]['vmware_hostname']
            else:
                vmname = vms[server][vm]['vmware_name']
            inventory['all_vms']['hosts'].append(vmname)

            for k, v in vms[server][vm].iteritems():
                for group in options['vmware']['groups'].split(','):
                    if k == group:
                        if not v in inventory:
                            inventory[v] = {
                                'hosts' : []
                            }
                        inventory[v]['hosts'].append(vmname)
                if not vmname in inventory['_meta']['hostvars']:
                    inventory['_meta']['hostvars'][vmname] = {}
                inventory['_meta']['hostvars'][vmname][k] = v

    print json.dumps(inventory, indent=4)
    



###############################################################################
#
# Build a disctionary of all VMs and specified properties
#
###############################################################################
def get_vm_list(options):

    all_vms = {}

    for server in options['vmware']['servers'].split(','):

        s = vcenter_connect(server,options['vmware']['username'],options['vmware']['password'])

        try:
            props = s._retrieve_properties_traversal(property_names=options['vmware']['properties'], obj_type='VirtualMachine')
        except Exception as e:
            print "[Error}: Invalid propery name in: ", options['vmware']['properties']
            sys.exit(1)

        if not server in all_vms:
            all_vms[server] = {}

        for obj in props:
            if not obj.Obj in all_vms[server]:
                all_vms[server][obj.Obj] = {}

            for prop in obj.PropSet:
                all_vms[server][obj.Obj]["vmware_" + str(prop.Name.split('.')[-1])] = prop.Val
            all_vms[server][obj.Obj]['hosting'] = 'vmware'

        s.disconnect()

    return all_vms





if __name__ == '__main__':

    options = get_options()

    args = parse_args(options)

    vms = get_vm_list(options)

    if args.list:
        ansible_list(options, vms)
    elif args.host:
        ansible_host(options, vms)
    elif args.vms:
        ansible_vms(options, vms)
    else:
        for server in vms:
            for vm in vms[server]:
                for k, v in vms[server][vm].iteritems():
                    print server, "==>", vm, "-->", k, ": ", v

    sys.exit(0)
