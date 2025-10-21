import os
import requests
# TODO: CHANGE BEFORE COMPE
URL_API = 'http://host.docker.internal:3232/api/'
def _fetch_teams():
    resp = requests.get(URL_API + 'user')
    if resp.status_code == 200:
        resp = resp.json()
    else:
        raise Exception(f'Status code not success: {resp.status_code}')
        
    data = {
        f"{x['username']} [Team #{x['id']}]": x['host_ip']
        for x in resp
    }
    
    return data

CONFIG = {
    'DEBUG': os.getenv('DEBUG') == '1',

    'TEAMS': _fetch_teams(),
    # 'FLAG_FORMAT': r'CTF\.Moscow\{[a-zA-Z\.0-9_-]+\}',
    # 'FLAG_FORMAT': r'VolgaCTF{[\w-]*\.[\w-]*\.[\w-]*}',
    'FLAG_FORMAT': r'[A-Z0-9]{31}=',

    # 'SYSTEM_PROTOCOL': 'ructf_http',
    # 'SYSTEM_URL': 'http://monitor.ructfe.org/flags',
    # 'SYSTEM_TOKEN': '275_17fc104dd58d429ec11b4a5e82041cd2',

    # Currently used protocol is for WreckIT
    'SYSTEM_PROTOCOL': 'wreckit_http',
    
    'SYSTEM_URL': URL_API + 'flag',
    # TODO: CHANGE BEFORE COMPE
    'SYSTEM_TOKEN': '4fdcd6e54faa8991',
    # - TO HERE
    
    # 'SYSTEM_PROTOCOL': 'volgactf',
    # 'SYSTEM_VALIDATOR': 'volgactf',
    # 'SYSTEM_HOST': 'final.volgactf.ru',
    # 'SYSTEM_SERVER_KEY': validators.volgactf.get_public_key('https://final.volgactf.ru'),

    # The server will submit not more than SUBMIT_FLAG_LIMIT flags
    # every SUBMIT_PERIOD seconds. Flags received more than
    # FLAG_LIFETIME seconds ago will be skipped.
    'SUBMIT_FLAG_LIMIT': 100,
    'SUBMIT_PERIOD': 2,
    'FLAG_LIFETIME': 5 * 60,

    # VOLGA: Don't make more than INFO_FLAG_LIMIT requests to get flag info,
    # usually should be more than SUBMIT_FLAG_LIMIT
    # 'INFO_FLAG_LIMIT': 10,

    # Password for the web interface. This key will be excluded from config
    # before sending it to farm clients.
    # ########## DO NOT FORGET TO CHANGE IT ##########
    'SERVER_PASSWORD': 'frontshotsgaming',

    # For all time-related operations
    'TIMEZONE': 'Europe/Moscow',
}
