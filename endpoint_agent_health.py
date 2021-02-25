from pprint import pprint
import requests
from getpass import getpass
from datetime import datetime, timedelta, timezone

## Set variable for a timeframe of the past 7 days
datecompare = datetime.now(timezone.utc) - timedelta(days=7)
datecompare = datecompare.strftime("%Y-%m-%d %H:%M:%S")

########################
### JIRA SERVER INFO ###
########################
jira_user = '[JIRA_Username]'
jira_password = '[JIRA_Password]'
jira_url = 'https://[JIRA_url]/rest/api/2/'
## In the call below we point to your inventory project, declare maximum results
## and specify a key. We used: project=INV, maxResults=5000, key=summary
inv_response = requests.get(jira_url + 'search?jql=project%3DINV&maxResults=5000&fields=key%2C%20summary',
                            auth=(jira_user, jira_password), headers={'Accept': 'application/json'})
jira_inventory = inv_response.json()
status = {}

###################
### CODE42 INFO ###
###################
username = '[Code42_API_User]'
c42passwd = getpass()
params = {'pgSize': '5000'}
c42response = requests.get('https://console.us.code42.com/api/Computer', auth=(username, c42passwd), params=params)
allinfo = c42response.json()

#################
### JAMF INFO ###
#################
user = '[JAMF_user]'
passwd = getpass()
jamfheaders = {
    'Accept': 'application/json',
}
jamfurl = 'https://[JAMF_url]/JSSResource/'
response = requests.get(jamfurl + 'computers', headers=jamfheaders)
inventory = response.json()

########################
### CrowdStrike Info ###
########################
tokenheaders = {
    'accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded',
}
tokendata = {
  'client_id': '[CS_client_id]',
  'client_secret': '[CS_client_secret]'
}
tokenresponse = requests.post('https://api.crowdstrike.com/oauth2/token', headers=tokenheaders, data=tokendata)
token = tokenresponse.json()
headers = {
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + token['access_token'],
    'cache-control': 'no-cache',
}
## That love letter I wrote? Here it is!
## Request a list of ALL unique CrowdStrike IDs registered to our account.
## Not currently used in our script, but very useful should you need it.
response = requests.get('https://api.crowdstrike.com/devices/queries/devices/v1?limit=5000', headers=headers)
csinfo = response.json()
correlation = {}
## Iterate through unique CrowdStrike IDs gathered in the step above
## Make an API call for each 
for csids in csinfo['resources']:
    compresponse = requests.get('https://api.crowdstrike.com/devices/entities/devices/v1?ids='
                                + csids, headers=headers)
    compinfo = compresponse.json()
    try:
        snumber = compinfo['resources'][0]['hostname']
    except KeyError:
        snumber = 'n/a'
    correlation.update({snumber : compinfo['resources'][0]['device_id']})

###################################
### CrowdStrike Current Version ###
###################################
version_response = requests.get('https://api.crowdstrike.com/sensors/combined/installers/v1?limit=2&sort=release_date%7Cdesc&filter=platform%3A%22mac%22', headers=headers)
version_csinfo = version_response.json()
## Pull current CS agent version
current_version = (version_csinfo['resources'][0]['version'])
## Pull previous CS agent version.
current_version_minus = (version_csinfo['resources'][1]['version'])

#####################
### Umbrella Info ###
#####################
umbrellaurl = 'https://management.api.umbrella.com/v1/organizations/[Umbrella_org]/roamingcomputers'
umbrellaheaders = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': '[Basic_Umbrella_creds]'
}
querystring = {'limit': '1000'}
umbrellaresponse = requests.get(umbrellaurl, headers=umbrellaheaders, params=querystring)
umbrellainventory = umbrellaresponse.json()

## Print CSV fields. Certainly room for doing this different ways
print("JAMF ID,User,SN,Deployment Status,JAMF last contact,"
      "CS Agent ID,CrowdStrike last seen,CS Agent Status,Umbrella DeviceId,Umbrella last seen,"
      "C42 UID,C42 last checkin,C42 Alert States")
## Iterate through results of our JIRA search from above. 
for inv_count in jira_inventory['issues']:
    comp_name = inv_count['fields']['summary']
    ticket_num = inv_count['key']
    ## Pull custom "Computer Make" field within JIRA Inventory Project
    comp_response = requests.get(jira_url + 'issue/' + ticket_num + '?fields=customfield_15402%2C%20customfield_15403',
                                 auth=(jira_user, jira_password), headers={'Accept': 'application/json'})
    comp_info = comp_response.json()
    try:
        comp_make = comp_info['fields']['customfield_15403']['value']
    except TypeError:
        comp_make = 'n/a'
    ## Gather computer deployment status
    comp_status = comp_info['fields']['customfield_15402']['value']
    status.update({comp_name : comp_status})
    ## Only care about Deployed Apple laptops
    if comp_status == 'Deployed' and comp_make == 'Apple':
        jamfstatus = requests.get(jamfurl + 'computers/name/' + comp_name, headers=jamfheaders)
        jamfcompinfo = jamfstatus.json()
        ## Gather unique JAMF computer ID
        compid = str(jamfcompinfo['computer']['general']['id'])
        ## Gather JAMF last checkin date and time
        jamfcheckin = str(jamfcompinfo['computer']['general']['last_contact_time_utc'])
        csuuid = "n/a"
        user = "n/a"
        cs_up_to_date = "n/a"
        cslastseen = "n/a"
        umbrellalastseen = "n/a"
        umbrelladeviceid = "n/a"
        ## Gather User information from JAMF
        if jamfcompinfo['computer']['location']['username']:
            user = str(jamfcompinfo['computer']['location']['username'])
        ## Umbrella requires some special logic to match computers
        ## The Umbrella computer name depends on when during the computer standup
        ## process umbrella is installed.
        for umbrella_count in umbrellainventory:
            if comp_name == umbrella_count['name']:
                ## Gather Umbrella last seen date and time
                umbrellalastseen = umbrella_count['lastSync']
                ## Gather unique Umbrella DeviceID
                umbrelladeviceid = umbrella_count['deviceId']
        ## We have a script in JAMF which has devices run a CS command and gather
        ## their unique CrowdStrike ID and store it in a custom attribute
        ## Here we iterate through thouse custom attributes to pull that CS ID
        for extensions in jamfcompinfo['computer']['extension_attributes']:
            if str(extensions['name']) == 'CrowdStrike Agent ID':
                if str(extensions['value']) != '':
                    csuuid = str(extensions['value'])
                    csuuid = csuuid.lower()
                    csuuid = csuuid.replace('-', '')
                    try:
                        ## API call to CrowdStrike with unique CS ID
                        csresponse = requests.get('https://api.crowdstrike.com/devices/entities/devices/v1?ids=' + csuuid,
                                                  headers=headers)
                        csinfo = csresponse.json()
                        if csinfo['resources'][0]['agent_version']:
                            ##Set Agent Version
                            agent_version = csinfo['resources'][0]['agent_version']
                            ## Check if agent update is needed
                            if agent_version[:-2] not in [current_version, current_version_minus]:
                                cs_up_to_date = "Needs Update - " + agent_version
                            ## Check if CrowdStrike is up to date
                            elif agent_version[:-2] in [current_version, current_version_minus]:
                                cs_up_to_date = "OK - " + agent_version
                        ## Gather CrowdStrike last checkin date and time
                        if csinfo['resources'][0]['last_seen']:
                            cslastseen = csinfo['resources'][0]['last_seen']
                    ## Excemption for a device not being registered in CrowdStrike
                    except IndexError:
                        cslastseen = 'not in CrowdStrike'
        c42alert = 'n/a'
        c42checkin = 'n/a'
        c42uid = 'n/a'
        ## Iterate through devices in Code42
        for c42_count in allinfo['data']['computers']:
            if comp_name == c42_count['osHostname']:
                ## Due to Legal Hold, Code42 can have more than one entry per
                ## device. To make sure we are reporting on an actively used
                ## device we look for devices which have checked in within 7 days
                if datecompare <= str(c42_count['lastConnected']):
                    c42uid = str(c42_count['guid'])
                    c42checkin = str(c42_count['lastConnected'])
                    c42alert = str(c42_count['alertStates'])
        ## Print information gathered above
        print(compid + ',' + user + ',' + comp_name + ',' + comp_status + ',' + jamfcheckin + ',' + csuuid + ','
              + cslastseen + ',' + cs_up_to_date + ',' + umbrelladeviceid + ',' + umbrellalastseen + ',' + c42uid
              + ',' + c42checkin + ',' + c42alert)
