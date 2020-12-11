#ClearPass 9th September '20 Version DRAFT 0.3 derin.mellor@btinternet.com

WARNING: This is provided purely for testing. Only rudimentary testing has been done on this. 

This python code uses various ClearPass RESTful API calls to control connected devices.

	Usage: inject_threat <ip>|<mac> [-s|-t|-x] {role}
	where
	-s <mac|ip>	[Unknown|Known|Disabled] {role}		Update Endpoint Status
		Unknown needs only U or u
		Known needs only K or k
		Disabled needs only D or d
		
		If this is an IP ClearPass will interrogate the Endpoint profiles to get the associated MAC address. 
		It will then update the endpoint repository's Status as defined (ie Known, Unknown or Disabled)
		It will find if the device is online.
			If the role was defined this will be assigned.
			Otherwise, it will find the media - currently only supports Aruba switch or wireless.
				Aruba switch: Sends a RADIUS CoA PortBounce
				Wireless: Sends a RADIUS CoA Disconnect

	-t <mac|ip>	[Set|Clear] {role}					Update Endpoint Threat Status
		Set=Unresolved, only needs a S or s
		Clear=Resolved, only needs a C or c
	
		If this is an IP ClearPass will interrogate the Endpoint profiles to get the associated MAC address. 
		It will then update various endpoint attributes: 
			Threat Name=TEST
			Threat Severity=Critical
			Threat Timestamp=<current time>
			Threat Status=Unresolved or Resolved
		It will then find if the device is online.
			If the role was defined this will be assigned.
			Otherwise, it will find the media - currently only supports Aruba switch or wireless.
				Aruba switch: Sends a RADIUS CoA PortBounce
				Wireless: Sends a RADIUS CoA Disconnect

	-x <mac|ip>	{role} 								Delete Endpoint
		If this is an IP ClearPass will interrogate the Endpoint profiles to get the associated MAC address. 
			
		It will then delete the endpoint and CPG guest device repository.
		It will then find if the device is online.
			If the role was defined this will be assigned.
			If it is it will find the media - currently only supports Aruba switch or wireless.
				Aruba switch: Sends a RADIUS CoA PortBounce
				Wireless: Sends a RADIUS CoA Disconnect

WARNING: When using IP address problems can occur if the device is actually offline!
NOTE: This supports MAC addresses with the format of 01234567890abc, 01:23:45:68:89:0A:bC or 01-23-45-67-89-0a:Bc
NOTE: This does not support IPv6 addresses
 

ClearPass CPG setup
To run this program you need to create an API Client in CPG with the grant_type=password, eg
	ClientID				RESTtest
	Enabled					yes
	Operating Mode			ClearPass REST API - Cleint will be used for API calls to ClearPass
	Operating Profile		Super Administrator (NOTE API Guest Operator by default has limited access to the Endpoints)
	Grant Type				Username and password credentials (grant_type=password)
	Refresh Token			yes (though I don't use it!)
	Public Client			no
	Client Secret			initially yes
	Access Token Lifetime	8 hours
	Refresh Token Lifetime	14 days
	

ClearPass Policy Manager setup
Create a local user, my one is called test with the password aruba123.
Create a service using the OAuth2 API User Access template 
	Authentication Source = [Local User Repository]
	Enforcement 
		Default Profile				[Deny Application Access Profile]
		Rule Evaluation Algorithm	First Applicable 
		Condition1					Tips:Role EQUALS [User Authentcated] --> [Operator Login - Admin Users]
	

restfulapi.ini
The program is reliant on the restfulapi.ini file to setup and maintain the RESTful API's Bearer. This file must be located in same directory.

This file contains all the settings to setup and maintain the RESTful API connection to ClearPass:

	[restfulapi]
	clearpass=cppm.hpearubademo.com
	client_id=RESTtest
	client_secret=UcKXaBwcUolLDLbAs8Tjst6qcwvA/n5swCaD3x1gUQSc
	grant_type=password
	password=aruba123
	username=test
	access_token=0
	expires=1970/01/01 00:00:00
	refresh_token=0

Where:
	clearpass is hostname of ClearPass to interrogate
	client_id is the RESTful client ID on ClearPass
	client_secret is the RESTful client secret generated on ClearPass
	grant_type must be "password"
	username is the RESTful username on this grant type on ClearPass
	password is the RESTful password on this grant type on ClearPass
	access_token will be setup and maintained by program
	expires will be setup and maintained by program
	refresh_token will be setup and maintained by program

WARNING: This is not secure!!! The password is in cleartext!!! This is purely for testing!!!

When the program starts for the first time it will realise the access_token has expired. 
It will setup the access_token, expires and refresh_token. These will be recorded to this file.
Note: The order of these parameters is not important.