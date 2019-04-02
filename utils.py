from pymongo import MongoClient
from bs4 import BeautifulSoup
import datetime
import jdatetime
import string
import requests
import re

MONGO_HOST = "localhost"
MONGO_PORT = 27017
DB_NAME = 'atc_web_app'
AMHS_DB_NAME = 'amhs_log'
#Config MongoDB

def config_mongodb(mongo_host, mongo_port, db_name):
    uri = "mongodb://{}:{}".format(
        mongo_host,
        mongo_port
    )
    cur = MongoClient(uri)[db_name]
    return cur

cursor = config_mongodb(MONGO_HOST, MONGO_PORT, DB_NAME)


def file_empty_logs():
    last_inserted_id = cursor.records.estimated_document_count()
    result = cursor.records.find_one({"id": last_inserted_id})
    d = datetime.datetime.strptime(result['shift_date'], '%Y - %m - %d')
    if jdatetime.datetime.now().month > 6:
        A = 3
        B = 15
    else:
        A = 2
        B = 14
    if result['shift'] == "N":
        d = d + datetime.timedelta(days=1)
        end_of_last_duty = d.replace(day=d.day, hour=A, minute=30, second=0, microsecond=0)
    else:
        end_of_last_duty = d.replace(day=d.day, hour=B, minute=30, second=0, microsecond=0)

    h = 12
    while True:
        if datetime.datetime.utcnow() >= end_of_last_duty:
            if end_of_last_duty < datetime.datetime.utcnow() <= end_of_last_duty + datetime.timedelta(hours=h):
                break
            else:
                records = insert_empty_log(last_inserted_id, result['team'], result['shift'], result['day'],result['event_date'], result['shift_date'], result['shift_jdate'])
                cursor.records.insert_one(records)
            last_inserted_id = cursor.records.estimated_document_count()
            result = cursor.records.find_one({"id": last_inserted_id})
            end_of_last_duty = end_of_last_duty + datetime.timedelta(hours=h)
        else:
            break

def insert_empty_log(*args):
    records = {}
    records['id'] = args[0] + 1
    if int(args[1]) == 4:
        records['team'] = '1'
    elif int(args[1]) == 5:
        records['team'] = '2'
    else:
        records['team'] = str(int(args[1]) + 2)
    if args[2] == "D":
        records['shift'] = "N"
        records['shift_date'] = args[5]
        records['shift_jdate'] = args[6]
        records['day'] = args[3]
    else:
        records['shift'] = "D"
        records['shift_date'] = (datetime.datetime.strptime(args[5], '%Y - %m - %d')+datetime.timedelta(days=1)).strftime('%Y - %m - %d')
        records['shift_jdate'] = (datetime.datetime.strptime(args[6], '%Y - %m - %d')+datetime.timedelta(days=1)).strftime('%Y - %m - %d')
        if int(args[3]) > 6:
            records['day'] = str(1)
        else:
            records['day'] = str(int(args[3]) + 1)
    records['event_date'] = args[4] + datetime.timedelta(hours=12)
    records['network'] = []
    records['on_duty'] = records['shift_switch'] = records['overtime'] = records['daily_leave'] = regex("")
    records['tsa_during'] = records['tsa_from'] = records['tsa_to'] = ""
    records['tsa_reason'] = records['tsa_end'] = records['tsa_lrls'] = ""
    records['sta_during'] = records['sta_from'] = records['sta_to'] = records['sta_reason'] = ""
    records['sta_end'] = records['sta_lrls'] = ""
    records['cfa_during'] = records['cfa_from'] = records['cfa_to'] = records['cfa_reason'] = ""
    records['cfa_end'] = records['cfa_lrls'] = records['tia_during'] = records['tia_from'] = ""
    records['tia_to'] = records['tia_reason'] = records['tia_end'] = records['tia_lrls'] = ""
    records['mca_during'] = records['mca_from'] = records['mca_to'] = records['mca_reason'] = ""
    records['mca_end'] = records['mca_lrls'] = records['fpl'] = records['dla'] = ""
    records['chg'] = records['notam'] = records['perm'] = records['remarks'] = ""
    records['signature_path']=[]
    return records

def regex(S):
    letters = list(string.ascii_uppercase)
    pattern = ''
    pattern_list = []
    result_list = []
    for s in S:
        if s not in letters:
            pattern = pattern + s
    if pattern:
        for i in pattern:
            if i not in pattern_list:
                pattern_list.append(i)
        split_result = re.split(str(pattern_list), S)
        for j in split_result:
            if len(j)!=0:
                result_list.append(j)
    else:
        result_list.append(S)
    return result_list

def fetch_day(day_num):
    if day_num == '1':
        wd = 'Monday'
    elif day_num == '2':
        wd = 'Tuesday'
    elif day_num == '3':
        wd = 'Wednesday'
    elif day_num == '4':
        wd = 'Thursday'
    elif day_num == '5':
        wd = 'Friday'
    elif day_num == '6':
        wd = 'Saturday'
    elif day_num == '7':
        wd = 'Sunday'
    return wd

def fetch_day_num(wd):
    if wd == 'Monday':
        day = '1'
    elif wd == 'Tuesday':
        day = '2'
    elif wd == 'Wednesday':
        day = '3'
    elif wd == 'Thursday':
        day = '4'
    elif wd == 'Friday':
        day = '5'
    elif wd == 'Saturday':
        day = '6'
    elif wd == 'Sunday':
        day = '7'
    return day

def fa_airports_name_to_en_name(fa_name):
    airports_fa_name = ["تهران", "مشهد", "شیراز", "کیش", "قشم", "اهواز", "کرمانشاه", "بندرعباس", "عسلویه", "اصفهان"]
    airports_icao_name = ["OIII", "OIMM", "OISS", "OIBK", "OIKQ", "OIAW", "OICC", "OIKB", "OIBP", "OIFM"]
    if fa_name in airports_fa_name:
        index = airports_fa_name.index(fa_name)
        en_name = airports_icao_name[index]
    else:
        en_name = "not in list"
    return en_name

def name_related_initial(name, members):
    for member in members:
        if name == member[0]:
            return member[1]
    return name

def metar(airport):
    time = datetime.datetime.utcnow().strftime('%d%H')
    if airport == 'OICC':
        html = "https://aviationweather.gov/adds/metars/index?submit=1&station_ids=OICC&chk_metars=on&hoursStr=2&std_trans=translated&chk_tafs=on"
    else:
        html = ""

    if html:
        try:
            r = requests.get(html).text
            soup = BeautifulSoup(r, "html.parser")
            for tr in soup.find_all('tr'):
                tds = tr.find_all('td')
                #print(type(tds))
                if len(tds):                
                    #print('OICC')
                    l_tds = []
                    for i in range(2,len(tds)):
                        if ("OICC" and time) in tds[i].text:
                            return tds[i].text
        except requests.exceptions.RequestException as e:
            print(e)
            return ""

def shift_brief(result, department):
    l = []
    if department == 'Aeronautical Information and Communication Technology':
        l.append(result['shift_date'])
        l.append(result['shift_jdate'])
        l.append(result['on_duty'])
        l.append(result['team'])
        l.append(result['day'])
        l.append(result['shift'])
    elif department == 'Air Traffic Management':
        l.append(result['shift_date'])
        l.append(result['shift_jdate'])
        l.append(result['hand_over_to'])
        l.append((", ".join(result['present_members'])))
        l.append(result['team'])
        l.append(result['week_day'])
        l.append(result['shift'])
        l.append(result['rwy_in_use'])
    return l

def if_today_shift(result):
    wd = datetime.datetime.today().weekday()
    d = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    jd = jdatetime.datetime.now().strftime('%Y - %m - %d')
    today = d

    if jdatetime.datetime.now().month > 6:
        A = datetime.time(3, 30)
        B = datetime.time(15, 30)
    else:
        A = datetime.time(2, 30)
        B = datetime.time(14, 30)

    if A <  datetime.datetime.utcnow().time() <= B:
        today_shift = 'Day'
        today_wd = fetch_day(str(wd+1))
    elif datetime.datetime.utcnow().time() <= A:
        d = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
        jd = (jdatetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
        today = d
        today_shift = 'Night'
        today_wd = fetch_day(str(wd))
    else:
        today_shift = 'Night'
        today_wd = fetch_day(str(wd+1))

    if today==result['shift_date'] and today_shift==result['shift']:
        return True
    else:
        return False

def notam_processing(notam):
    m = re.search('ZCZC (\w+)', notam)
    tsa = m.groups()[0] if m else None
    m = re.search('\((\w+/\w+)', notam)
    notam_no = m.groups()[0] if m else None
    m = re.search('A\)(\w+)', notam)
    aero = m.groups()[0] if m else None
    m = re.search('E\)([\s\S]+)', notam)
    e = m.groups()[0] if m else None
    e = ("E)"+(e.replace(')', '')).replace('NNNN', '')).rstrip()
    processed_notam = [tsa, notam_no, aero, e]
    return processed_notam

def permission_processing(perm):
    m = re.search('ZCZC (\w+)', perm)
    tsa = m.groups()[0] if m else None
    m = re.search('OUR REF(.+)', perm)
    perm_ref = m.groups()[0] if m else None
    if perm_ref:
        perm_ref = ((perm_ref.rstrip()).replace(" ", '')).replace(':', '')
    #m = re.search('QTE\r\n(\w+)', perm)
    #org_ref = m.groups()[0] if m else None
    m = re.findall('\r\n(\d{6} )', perm)
    org_ref = m if m else None
    if (org_ref) and (len(org_ref) > 1):
        org_ref = (org_ref[1]).replace(' ', '')
        print(org_ref)
    m = re.search('FROM:(.+)', perm)
    From = m.groups()[0] if m else None
    m = re.search('OPERATOR:(.+)', perm)
    operator = m.groups()[0] if m else None
    m = re.search('IR FPN(.+)', perm)
    ir_fpn = m.groups()[0] if m else None
    m = re.search('PERMISSION IS (\w+)', perm)
    gr = m.groups()[0] if m else None
    if not gr:
        granted = 'NO'
    elif gr == 'GRANTED':
        granted = 'YES'
    else:
        granted = None
    m = re.search('REF YR MSG (\s\w+)', perm)
    granted_ref = m.groups()[0] if m else None
    if granted_ref:
        granted_ref = granted_ref.replace(' ', '')
    processed_permission = [tsa, perm_ref, From, operator, ir_fpn, granted, org_ref, granted_ref]
    return processed_permission

def notam_permission_data(result, cursor):
    if result['notam']:
        result_notam = cursor.notam.find({"id": result['id']})
        notam_tsa = []
        if result_notam:
            E = []
            notam_no = []
            for item in result_notam:
                notam_tsa.append(item['tsa'])
                E.append(item['E'])
                notam_no.append(item['notam_no'].replace('/', '-'))
        else:
            E = None
            notam_no = None
        notam_data = {'notam_tsa': notam_tsa, 'E':E, 'notam_no':notam_no}
    else:
        notam_data = None
    if result['perm']:
        result_permission = cursor.permission.find({"id": result['id']})
        if_granted = []
        granted = []
        ir_fpn = []
        perm_tsa = []
        ref = []
        gr = ""
        if result_permission:
            for item in result_permission:
                if item['granted'] == 'YES':                    
                    gr = '''PERMISSION IS GRANTED!
IR FPN: '''                  
                else:
                    gr = '''
            OK SENT.
GRANTED NOT RECIEVED!
IR FPN: '''
                perm_tsa.append(item['tsa'])
                granted.append(gr)
                if_granted.append(item['granted'])
                ir_fpn.append(item['ir fpn'])
                perm_tsa.append(item['tsa'])
                ref.append(item['perm_ref'].replace('/', '-'))
        else:
            ref = None
        perm_data = {'perm_tsa':perm_tsa, 'granted':granted, 'if_granted':if_granted,
        'ir_fpn':ir_fpn, 'perm_tsa':perm_tsa, 'ref':ref}
    else:
        perm_data = None

    return (notam_data, perm_data)