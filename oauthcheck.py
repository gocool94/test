import requests
from mimir import Mimir
from generic_utilities import setup_logging, generic_config_parser, handle_error

login_url = 'https://cloudsso.cisco.com/as/token.oauth2?client_id=nossplunknpres.gen&grant_type=client_credentials&client_secret=$NP-USrobot4&scope=openid'
r = requests.post(login_url)
token = r.json()
print token

mimir_url = 'https://mimir-prod.cisco.com/api/mimir/np/last_profile_details?cpyKey=4164'
#response = requests.get(mimir_url, headers={ 'Authorization': 'Bearer '+token['access_token'] })
#print response.text

#print(m.__dict__)
def mimir_connect():
    login_url = 'https://cloudsso.cisco.com/as/token.oauth2?client_id=nossplunknpres.gen&grant_type=client_credentials&client_secret=$NP-USrobot4&scope=openid'
    r = requests.post(login_url)
    token = r.json()
    print token

    g_conf = generic_config_parser()
    user_section = "mimir_user"
    user_credentials = g_conf.fetch_conf_param(user_section)
    mimir_env = g_conf.fetch_conf_param("mimir_env")
    print mimir_env["url"]
    #mimir_instance = Mimir(cookies ={"access_token": token['access_token']},url=mimir_env["url"])
    #m.authenticate(user='nossplunknpres.gen',password='$NP-USrobot5')
    print token['access_token']
    mimir_instance = Mimir(access_token=token['access_token'],url=mimir_env["url"])
    return mimir_instance
m = mimir_connect()
collector_details = m.np.collector_details.get(cpyKey=77760)
print collector_details
for i in collector_details:
    print(i)
