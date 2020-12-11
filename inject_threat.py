#!/usr/bin/env python3
#
# The purpose of this code is to learn Python3 and using ClearPass RESTful API
# 
# This program allows you to control the Endpoint's state - see usage message
#
# WARNING: This is provided purely for testing. Only rudimentary testing has been done on this. 
#
# Author:	Derin Mellor
# @mail:	derin.mellor@btinternet.com
# Date:		12th August '20
# Version:	0.2
#
from datetime import datetime, timedelta
import configparser
import json
import os
import re
import sys
import requests
import socket
import time


############################################# 
# Verify the MAC address is valid
def usage(argv):
	print('Usage:', argv[0], '-s <ip>|<mac> [Known|Unknown|Distabled] {role}')
	print('Usage:', argv[0], '-t <ip>|<mac> [Set|Clear] {role}')
	print('Usage:', argv[0], '-x <ip>|<mac> {role}')
	print('where')
	print('\t-s: Create/Update Endpoint\'s state: Known, Unkown or Disabled')
	print('\t-t: Set/Clear Endpoint\'s Threat Status')
	print('\t-x: Delete endpoint')
	print('If using IP address there must be an associated MAC address')
	print('NOTE if the role is not defined it will use:')
	print('\tWired\t\tiAruba switch CoA Bounce Port')
	print('\tWireless\tAruba wireless CoA Disconnect Message')
	print('If it is defined this role will be directly applied')
	return 


############################################# 
# Verify the MAC address is valid
def valid_mac(address):

#	print('Entering valid_mac', address)
	try:
		if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", address.lower()):
			return True
	except:
		return False


############################################# 
# Verify the IP address is valid
def valid_ip(address):
	try:
		socket.inet_aton(address)
		return True
	except:
		return False


############################################# 
# Parse postgresql details file
def configdb(filename, section):

#	print('Enter configdb, filename=',filename,' section=',section)
	parser = configparser.ConfigParser()
	parser.read(filename)
	db={}
	if parser.has_section(section):
		params = parser.items(section)
		for param in params:
#			print('Param1:',param[0], '\tParam2:', param[1])
			db[param[0]] = param[1]
	else:
		raise Exception('Section {0} not found in the {1}'.format(section, filename))
#	print('Leaving configdb, params=', db)
	return db


############################################# 
# Setup the Bearer using OpenAuth
def setup_bearer(restinfo):

#	print('Entering setup_bearer')

	access_token='Error'
	url = 'https://'+restinfo['clearpass']+':443/api/oauth'
#	print('URL=', url)
	payload = {'client_id':restinfo['client_id'], 'client_secret':restinfo['client_secret'], 'grant_type':restinfo['grant_type'], 'username':restinfo['username'], 'password':restinfo['password']}
#	print('payload=', payload)
	
# Using the json format automatically converts the body to correct "" form 
# and adds a Content-Type=application/json header 
	r = requests.post(url, json=payload)

	if r.status_code != 200:
		print('setup_bearer: Error=', r.status_code)
		return access_token
	fields = json.loads(r.content.decode('ascii'))
#	print('Fields', fields)
	
	access_token = fields["access_token"]
		# Make expire time 5 mins earlier so that if it is close... 
	expires_at = datetime.now() + timedelta(seconds=int(fields["expires_in"])-300)
	refresh_token = fields["refresh_token"].encode("ascii")
#	print('Access_Token=', access_token, 'expires_at=', expires_at, 'refresh_token=', refresh_token)
	return access_token, expires_at, refresh_token


############################################# 
# GET Active Session for this MAC address
def get_active_session(mac, clearpass, authorization):

#	print("GET Active Session for MAC", mac)
	url = 'https://'+clearpass+':443/api/session?filter=%7B%22mac_address%22%3A%22'+mac+'%22%2C%22acctstoptime%22%3A%7B%22%24exists%22%3Afalse%7D%7D&sort=-acctstarttime&offset=0&limit=1&calculate_count=true'

	r = requests.get(url, headers=authorization);

	if r.status_code != 200:
		print('get_active_session: status_code=', status_code)
		return 0, 'None'
	fields = json.loads(r.content.decode('ascii'))
#	print('fields=', fields)

#	print('Count', fields['count'])
	if fields['count'] == 0:
		print('No active session')
		return 0, 'None'

	if fields['_embedded']['items'][0]['state'] != "active":
			# No active session
		session_id=0
		media=0
	else:
		session_id=fields['_embedded']['items'][0]['id']
		media=fields['_embedded']['items'][0]['nasporttype']
#			!!! Need to add a check to see that this is not a stale device

#	print('Active Session_ID', session_id, 'Media', media)
	return session_id, media


############################################# 
# GET Endpoint details using either MAC address
def get_endpoint(mac, clearpass, authorization):

#	print('Entering get_endpoint, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# get profile information
	url = 'https://'+clearpass+':443/api/endpoint?filter=%7B%22mac_address%22%3A%22'+mac+'%22%7D&sort=%2Bid&offset=0&limit=1&calculate_count=true'
#	print("URL=", url)
	
	r = requests.get(url, headers=authorization);
	
	if r.status_code != 200:
		print('get_endpoint: Failed to get Endpoint status=', r.status_code)

	fields = json.loads(r.content.decode('ascii'))
	count=fields["count"];

#	print('Leaving get_endpoint, status=', r.status_code)
	return count


############################################# 
# GET Endpoint details using IP address
def get_mac(ip, clearpass, authorization):

#	print('Entering get_mac, ip=',ip,'ClearPass=',clearpass,'Authorization=',authorization)
		# Use the Endpoint profile to find the device's MAC address
	url = 'https://'+clearpass+':443/api/device-profiler/device-fingerprint/'+ip
#	print('URL=',url)

	r = requests.get(url, headers=authorization);
	if r.status_code == 404:
		return ""
	elif r.status_code != 200:
		print('get_mac: Failed to get Endpoint Profile by IP', ip, 'status=', r.status_code)
		return ""

	fields = json.loads(r.content.decode('ascii'))
	mac=fields["mac"]
	updated_at=datetime.fromtimestamp(fields["updated_at"])
#	print('mac=',mac,'updated_at',updated_at)
	if mac == "":
		print('get_mac: Endpoint IP does not have a mac address')
		return ""
	if mac.startswith("x"):	# ignore synthetic MACs
		print('get_mac: Endpoint IP does not have a mac address')
		return ""

	if updated_at < (datetime.now() - timedelta(hours=2)):
		print('get_mac: No active session for that IP address')
		return ""

#	print('Leaving get_mac, mac=', mac)
	return mac


############################################# 
# POST Create Endpoint as Known
def post_endpoint_create_known(mac, clearpass, authorization):

#	print('Entering post_endpoint_create_known, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# get profile information
	url = 'https://'+clearpass+':443/api/endpoint'
#	print("URL=", url)
	payload = {'mac_address':mac,'status':'Known'}
#	print('payload=',payload)
	
	r = requests.post(url, headers=authorization, json=payload);
	
	if r.status_code != 201:
		print('post_endpoint_create_known: Failed to create Endpoint status=', r.status_code)

#	print('Leaving post_endpoint_create_known, status=', r.status_code)
	return r.status_code


############################################# 
# POST Create Endpoint as Unknown
def post_endpoint_create_unknown(mac, clearpass, authorization):

#	print('Entering post_endpoint_create_unknown, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# get profile information
	url = 'https://'+clearpass+':443/api/endpoint'
#	print("URL=", url)
	payload = {'mac_address':mac,'status':'Unknown'}
#	print('payload=',payload)
	
	r = requests.post(url, headers=authorization, json=payload);
	
	if r.status_code != 201:
		print('post_endpoint_create_unknown: Failed to create Endpoint status=', r.status_code)

#	print('Leaving post_endpoint_create_unknown, status=', r.status_code)
	return r.status_code


############################################# 
# POST Create Endpoint as Disabled
def post_endpoint_create_disabled(mac, clearpass, authorization):

#	print('Entering post_endpoint_create_disabled, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# get profile information
	url = 'https://'+clearpass+':443/api/endpoint'
#	print("URL=", url)
	payload = {'mac_address':mac,'status':'Disabled'}
#	print('payload=',payload)
	
	r = requests.post(url, headers=authorization, json=payload);
	
	if r.status_code != 201:
		print('post_endpoint_create_disabled: Failed to create Endpoint status=', r.status_code)

#	print('Leaving post_endpoint_create_disabled, status=', r.status_code)
	return r.status_code


############################################# 
# PATCH Endpoint MAC address with Known
def patch_endpoint_known(mac, clearpass, authorization):

#	print(patch_endpoint_known, mac=', mac, 'ClearPass=',clearpass, 'Authorization=',authorization)
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
#	print('URL=',url)
	payload = {'status':'Known'}
#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload);
	
#	print('status_code=',r.status_code)
	if r.status_code != 200:
		print('patch_endpoint_known: Failed to update Endpoint Known, status=', r.status_code)

#	print('Leaving patch_endpoint_known, status=', r.status_code)
	return r.status_code
	

############################################# 
# PATCH Endpoint MAC address with Unknown
def patch_endpoint_unknown(mac, clearpass, authorization):

#	print(patch_endpoint_unknown, mac=', mac, 'ClearPass=',clearpass, 'Authorization=',authorization)
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
#	print('URL=',url)
	payload = {'status':'Unknown'}
#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload);
	
#	print('status_code=',r.status_code)
	if r.status_code != 200:
		print('patch_endpoint_known: Failed to update Endpoint Unknown, status=', r.status_code)

#	print('Leaving patch_endpoint_unknown, status=', r.status_code)
	return r.status_code
	

############################################# 
# PATCH Endpoint MAC address with Disabled
def patch_endpoint_disabled(mac, clearpass, authorization):

#	print('patch_endpoint_disabled, mac=', mac, 'ClearPass=',clearpass, 'Authorization=',authorization)
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
#	print('URL=',url)
	payload = {'status':'Disabled'}
#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload);
	
#	print('status_code=',r.status_code)
	if r.status_code != 200:
		print('patch_endpoint_disabled: Failed to update Endpoint Disabled, status=', r.status_code)

#	print('Leaving patch_endpoint_disabled, status=', r.status_code)
	return r.status_code
	

############################################# 
# PATCH Endpoint MAC address with Threat details
def patch_endpoint_set_threat(mac, clearpass, authorization):

#	print('Entering patch_endpoint_set_threat, mac=', mac, 'ClearPass=',clearpass, 'Authorization=',authorization)
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
# Get date/time in YYYY-mm-dd hh:mm:ss format
#	print('URL=',url)
	now = datetime.now()
	time = now.strftime("%Y-%m-%d %H:%M:%S")
	payload = {'attributes':{'Threat Name':'TEST', 'Threat Severity':'Critical','Threat Timestamp':time, 'Threat Status':'Unresolved'}}
#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload);
	
#	print('status_code=',r.status_code)
	if r.status_code != 200:
		print('patch_endpoint_set_threat: Failed to update Endpoint, status=', r.status_code)
	else:
		print('Successfully updated')
		print('\tThreat Name=TEST')
		print('\tThreat Severity=Critical')
		print('\tThreat Timestamp=', time)
		print('\tThreat Status=Unresolved')

#	print('Leaving patch_endpoint_set_threat, status=', r.status_code)
	return r.status_code
	

############################################# 
# PATCH Endpoint MAC address with Threat Status Resolved
def patch_endpoint_threat_resolved(mac, clearpass, authorization):

#	print('Entering patch_endpoint_threat_resolved, mac=', mac, 'ClearPass=',clearpass, 'Authorization=',authorization)
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
#	print('URL=',url)
	payload = {'attributes':{'Threat Status':'Resolved'}}
#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload);
	
	if r.status_code != 200:
		print("patch_endpoint_threat_resolved: Failed to update Endpoint, status=", r.status_code)

#	print('Leaving patch_endpoint_threat_resolved, status=', r.status_code)
	return r.status_code
	

############################################# 
# DELETE Endpoint details using either MAC or IP address
def delete_endpoint(mac, clearpass, authorization):

#	print('Entering delete_endpoint, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# delete profile information
	url = 'https://'+clearpass+':443/api/endpoint/mac-address/'+mac
#	print("URL=", url)
	
	r = requests.delete(url, headers=authorization);
	
	if r.status_code == 404:
		print('Delete Endpoint: Does not exist')
	elif r.status_code != 204:
		print('delete_endpoint: Failed to delete Endpoint status=', r.status_code)

#	print('Leaving delete_endpoint: status=', r.status_code)
	return r.status_code
	

############################################# 
# DELETE CPG Device details using either MAC or IP address
def delete_cpg_device(mac, clearpass, authorization):

#	print('Entering delete_cpg_device, mac=',mac,'ClearPass=',clearpass,'Authorization=',authorization)
		# delete profile information
	url = 'https://'+clearpass+':443/api/device/mac/'+mac+'?change_of_authorization=false'
#	print("URL=", url)
	
	r = requests.delete(url, headers=authorization);
	
	if r.status_code == 404:
		print('Delete CPG Device: Does not exist')
	elif r.status_code != 204:
		print('delete_cpg_device: Failed to delete Endpoint, status=', r.status_code)

#	print('Leaving delete_cpg_device: status=', r.status_code)
	return r.status_code
	

############################################# 
# CREATE CPG Device details using MAC address
def create_cpg_device(mac, state, clearpass, authorization):

#	print('Entering create_cpg_device, mac=',mac,'State=',state,'ClearPass=',clearpass,'Authorization=',authorization)
		# create profile information
	url = 'https://'+clearpass+':443/api/device?change_of_authorization=false'
#	print("URL=", url)
	if state=='Known':
		payload = {'mac':mac, 'expire_time':0, 'sponsor_name':'inject_threat', 'enabled':True, 'role_id':3, 'mac_auth':True}

	if state=='Unknown':
		ticks = time.time()
		payload = {'mac':mac, 'expire_time':ticks, 'sponsor_name':'inject_threat', 'enabled':True, 'role_id':2, 'mac_auth':True}

	elif state=="Disabled":
		ticks = time.time()
		payload = {'mac':mac, 'expire_time':ticks, 'sponsor_name':'inject_threat', 'enabled':False, 'role_id':3, 'mac_auth':True}

#	print('payload=',payload)
	
	r = requests.post(url, headers=authorization, json=payload);
	
	if r.status_code != 201:
		print('create_cpg_device: Failed to create Endpoint, status=', r.status_code)

#	print('Leaving create_cpg_device: status=', r.status_code)
	return r.status_code
	

############################################# 
# PATCH CPG Device details using MAC address
def patch_cpg_device(mac, state, clearpass, authorization):

#	print('Entering patch_cpg_device, mac=',mac,'State=',state,'ClearPass=',clearpass,'Authorization=',authorization)

		# Verify device already exists CPG
	url = 'https://'+clearpass+':443/api/device?filter=%7B%22mac%22%3A%20%22'+mac+'%22%7D&sort=-id&offset=0&limit=25&calculate_count=true'
#	print("URL=", url)
	r = requests.get(url, headers=authorization)
	if r.status_code != 200:
		print('patch_cpg_device: WTF status_code=', status_code)
		return r.status_code
	fields = json.loads(r.content.decode('ascii'))
#	print('Count', fields['count'])
	if fields['count'] == 0:	# If does not exist - create!
		print('Endpoint does not exist in CPG - create!')
		status=create_cpg_device(mac, state, clearpass, authorization)
		return status

		# create profile information
	url = 'https://'+clearpass+':443/api/device/mac/'+mac+'?change_of_authorization=false'
#	print("URL=", url)

	if state=='Known':
		payload={'enabled':True, 'expire_time':0, 'role_id':3}

	if state=='Unknown':
		ticks = time.time()
		payload={'enabled':True, 'expire_time':ticks, 'role_id':2}

	elif state=='Disabled':
		ticks = time.time()
		payload={'enabled':False, 'expire_time':ticks, 'role_id':3}

#	print('payload=',payload)
	
	r = requests.patch(url, headers=authorization, json=payload)

	if r.status_code != 200:
		print('patch_cpg_device status_code', r.status_code)

#	print('Leaving patch_cpg_device: complete')
	return r.status_code


############################################# 
# POST Active Session CoA Reauthorize this session
def post_active_session_reauth(session_id, clearpass, authorization, role):

#	print('POST Active Session Reauthorize for session_id', session_id, 'with role ', role)
	url = 'https://'+clearpass+':443/api/session/'+str(session_id)+'/reauthorize'
#	print('URL=', url)

	payload = {'confirm_reauthorize': True, 'reauthorize_profile': role}
#	print('payload=', payload)

	r = requests.post(url, headers=authorization, json=payload);

	if r.status_code != 200:
		print('post_active_session_reauth: Failed to disconnect Endpoint, status=', r.status_code)
	else: print('Sent role', role, 'to Endpoint')
	return r.status_code
	

############################################# 
# POST Active Session CoA Disconnect this session
def post_active_session_disconnect(session_id, clearpass, authorization):

#	print("POST Active Session Disconnect for session_id", session_id)
	url = 'https://'+clearpass+':443/api/session/'+str(session_id)+'/disconnect'
	payload = {'confirm_disconnect': True}

	r = requests.post(url, headers=authorization, json=payload);

	if r.status_code != 200:
		print('post_active_sessions_disconnect: Failed to disconnect Endpoint, status=', r.status_code)
	else: print('Sent disconnect to Endpoint')
	return r.status_code
	

############################################# 
# Find active session and disconnect it
def disconnect_active_session(mac, role, clearpass, authorization):

	status = 0
	session_id, media = get_active_session(mac, clearpass, authorization)

	if session_id == 0:
		print('Disconnect_active_session: No active session')
		return status

		# If a role is passed apply it
	if role != "":
		status = post_active_session_reauth(session_id, clearpass, authorization, role)

	else:
		if media == "Ethernet":
			status = post_active_session_reauth(session_id, clearpass, authorization, "[ArubaOS Switching - Bounce Switch Port]")
		elif media == "Wireless-802.11":
			status = post_active_session_disconnect(session_id, clearpass, authorization)
		else: 
			print('Error: Not designed for media', media)

	return status


def main(argv):

	vars = len(sys.argv)
	if vars < 3 or vars > 5:
		usage(argv)
		sys.exit(1)

	mac=""
	ip=""
	if valid_ip(argv[2]):
		ip = argv[2]
#		print('IP address ', ip)
	elif valid_mac(argv[2]):
		mac = argv[2].lower()
#		print('MAC address ', mac)
	else:
		usage(argv)
		sys.exit(1)

	role = ""
	if vars>=4:
		text = argv[3]

	if vars==5:
		role = argv[4]

        # read RESTful API connection parameters
	params = configdb('restfulapi.ini', 'restfulapi')
	clearpass=params['clearpass']
	expires=params['expires']
	expires=datetime.strptime(expires, '%Y/%m/%d %H:%M:%S')
	access_token=params['access_token']
	bearer='Bearer '+access_token
	authorization = {'Authorization': bearer}

	if expires < datetime.now():
		print('RESTful session expired at', expires)
		print('Setup new session')
		access_token, expires_at, refresh_token=setup_bearer(params)
		print("Access_Token", access_token, "expires", expires_at)
		if access_token=='Error':
			print('Bearer setup failed, error', authorization)
			return
		bearer='Bearer '+access_token
		authorization = {'Authorization': bearer}

			# Update the ini file
		f = open('restfulapi.tmp', 'w')
		f.write('[restfulapi]\n')
		params['expires'] = expires_at.strftime('%Y/%m/%d %H:%M:%S')
		params['access_token'] = access_token
		params['refresh_token'] = refresh_token.decode('ascii')
		for param in params:
			line=param+'='+params[param]+'\n'
			f.write(line)
		f.close()
		os.rename('restfulapi.tmp','restfulapi.ini')

	if mac == "":
		mac=get_mac(ip, clearpass, authorization)
		if mac == "":
			print('This IP has no MAC address')
			usage(argv)
			return
		print('MAC address', mac)
		session_id, media = get_active_session(mac, clearpass, authorization)
		if session_id == 0:
			print('This IP has no active session')
			return

    # Update Endpoint's status
	if argv[1]=='-s' and vars>=4:
        # Update Endpoint Status Known - just needs a K or k
		if text.startswith('k') or text.startswith('K'):
				# check endpoint exists
			if get_endpoint(mac, clearpass, authorization) == 1:
					# update endpoint Known
				patch_endpoint_known(mac, clearpass, authorization)
				patch_cpg_device(mac, 'Known', clearpass, authorization)
                    # If role defined assign this role, otherwise for the device to disconnect 
				disconnect_active_session(mac, role, clearpass, authorization)
				print('Endpoint Known')

			else:		# create endpoint and set Known
				post_endpoint_create_known(mac, clearpass, authorization)
				create_cpg_device(mac, 'Known', clearpass, authorization)
				print('Endpoint created Known')

        # Update Endpoint Status Unknown - just needs a U or u
		elif text.startswith('u') or text.startswith('U'):
				# check endpoint exists
			if get_endpoint(mac, clearpass, authorization) == 1:
					# update endpoint Unknown
				patch_endpoint_unknown(mac, clearpass, authorization)
				patch_cpg_device(mac, 'Unknown', clearpass, authorization)
                    # If role defined assign this role, otherwise for the device to disconnect 
				disconnect_active_session(mac, role, clearpass, authorization)
				print('Endpoint Unknown')

			else:		# create endpoint and set Unknown
				post_endpoint_create_unknown(mac, clearpass, authorization)
				create_cpg_device(mac, 'Unknown', clearpass, authorization)
				print('Endpoint created Unknown')

        # Update Endpoint Status Disabled - just needs a D or d
		elif text.startswith('d') or text.startswith('D'):
				# check endpoint exists
			if get_endpoint(mac, clearpass, authorization) == 1:
					# update endpoint Disabled
				patch_endpoint_disabled(mac, clearpass, authorization)
				patch_cpg_device(mac, 'Disabled', clearpass, authorization)
                    # If role defined assign this role, otherwise for the device to disconnect 
				disconnect_active_session(mac, role, clearpass, authorization)
				print('Endpoint Disabled')
			else:		# create endpoint and set Disabled
				post_endpoint_create_disabled(mac, clearpass, authorization)
				create_cpg_device(mac, 'Disabled', clearpass, authorization)
				print('Endpoint created Disabled')
		else: usage(argv)

    # Update Endpoint's attributes, primarily the threat status to either Unresolved or Resolved
	elif argv[1]=='-t' and vars>=4:
		text = argv[3]
        # Set Endpoint threat status to Unresolved - just needs a S or s
		if text.startswith('s') or text.startswith('S'):
			print('Set Endpoint threat status = Unresolved')
			endpoint = get_endpoint(mac, clearpass, authorization) 
			if endpoint > 1:
				print('Endpoint has', endpoint, 'entries!!!')
				print('now what?')
				return
			elif endpoint == 0:	# If endpoint does not exist create...
				post_endpoint_create(mac, clearpass, authorization)
			patch_endpoint_set_threat(mac, clearpass, authorization)
                    # If role defined assign this role, otherwise for the device to disconnect 
			disconnect_active_session(mac, role, clearpass, authorization)
			print("Threat Set.")
        # Clear Endpoint threat status to Resolved - just needs a C or c
		elif text.startswith('c') or text.startswith('C'):
			print('Set Endpoint threat status = Resolved')
			patch_endpoint_threat_resolved(mac, clearpass, authorization)
                    # If role defined assign this role, otherwise for the device to disconnect 
			disconnect_active_session(mac, role, clearpass, authorization)
			print("Threat Cleared.")
		else: usage(argv)

    # Delete Endpoint
	elif argv[1]=='-x' and vars==3:
		delete_endpoint(mac, clearpass, authorization)
		delete_cpg_device(mac, clearpass, authorization)
            # If role defined assign this role, otherwise for the device to disconnect 
		disconnect_active_session(mac, role, clearpass, authorization)
		print('Endpoint deleted')
	
	else: 
		usage(argv)
		sys.exit(1)

	return


if __name__ == '__main__':
	main(sys.argv)
