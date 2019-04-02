from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, Markup
from flask_googlemaps import GoogleMaps, Map, icons
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from PIL import Image
from bs4 import BeautifulSoup
import io
from io import StringIO
import PIL.Image
import requests
import re
import codecs
import os
import json
import datetime
import jdatetime
import pdfkit
import pathlib
import utils, config

cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.DB_NAME)
amhs_cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.AMHS_DB_NAME)
UPLOAD_FOLDER = 'E:/AFTN-AMHS/Python/projects/Airport-Web-App/static/uploded_files/save_folder'
SAVE_FOLDER = 'E:/AFTN-AMHS/Python/projects/Airport-Web-App/static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)

app.secret_key = 'secret@atc_web_app@password_hash@840'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SAVE_FOLDER'] = SAVE_FOLDER
#set key as config for googlemaps
#app.config['GOOGLEMAPS_KEY'] = "AIzaSyBlWehb6tP8Fn5VqGEgcoounuDwx8k-mY8"
app.config['GOOGLEMAPS_KEY'] = "AIzaSyBU6HCTk7D2VgNHL-FJ6KSpDO0BQxPbuxw"
# Initialize the extension
GoogleMaps(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    session['log_no'] = cursor.log_records.estimated_document_count()
    session['amhs_log_no'] = amhs_cursor.records.estimated_document_count()
    session['initial'] = cursor.users.find_one({'username': session['username']})['initial']
    session['adsb_db'] = []
    session['statistics_flag'] = 0
    session['sorted_events'] = []
    session['metar'] = utils.metar("OICC")

    if session['log_no'] and (session['department'] == 'Air Traffic Management'):
        atc_result = cursor.log_records.find_one({"id": session['log_no']})
        if utils.if_today_shift(atc_result):
            session['log_records_list'] = utils.shift_brief(atc_result, session['department'])

    if session['amhs_log_no'] and (session['department'] == 'Aeronautical Information and Communication Technology'):
        amhs_result = amhs_cursor.records.find_one({"id": session['amhs_log_no']})
        if utils.if_today_shift(amhs_result):
            session['log_records_list'] = utils.shift_brief(amhs_result, session['department'])


    team_result = cursor.team.find()
    team_data = []
    all_members = []
    for r in team_result:
        team_data.append([r['team_number'], r['members']])
    for item in team_data:
        for sub in item[1]:
            all_members.append(sub)
    all_members.sort()
    session['all_members'] = all_members

    wd = []
    result_count_list = []
    flt_scheldule_dict = {}
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['log_data_flag'] = 0
    result = cursor.log_records.find({"id": session['log_no']})
    for key in result:
        if 'com_title' in key:
            session['filled_log_data_flag'] = 1            
        else:
            session['filled_log_data_flag'] = 0
    if not session.get('log_records_list', default=None):
        session['log_records_list'] = []
    WD = datetime.datetime.utcnow().weekday()
    today = utils.fetch_day(str(WD+1))
    result_count = cursor.flights_schedule.count_documents({"week_day": today})
    result = cursor.flights_schedule.find({"week_day": today})
    if result_count:
        wd.append(today)
        result_count_list.append(result_count)
        flt_scheldule_big_list = []
        for r in result:
            flt_scheldule_list = []
            flt_scheldule_list.append(today)
            flt_scheldule_list.append(r["arr_flt_no"])
            flt_scheldule_list.append(r["dep_flt_no"])
            flt_scheldule_list.append(r["airline"])
            flt_scheldule_list.append(r["arr_from"])
            flt_scheldule_list.append(r["dep_to"])
            flt_scheldule_list.append(r["arr_time"])
            flt_scheldule_list.append(r["dep_time"])
            flt_scheldule_list.append(r["type"])
            flt_scheldule_list.append(r["id"])
            flt_scheldule_big_list.append(flt_scheldule_list)
        flt_scheldule_dict[today] = flt_scheldule_big_list
    #return redirect(url_for('fids', airport='OICC', arr_dep="all"))

    return render_template('index.html',
        navigator="flight-schedule",
        flt_scheldule_dict=flt_scheldule_dict,
        week_days=wd,
        result_count_list=result_count_list,
        log_records_list=session['log_records_list']
        )

@app.route('/', methods=['GET', 'POST'])
def login():
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        result = cursor.users.find_one({"username": username})

        if result:
            if sha256_crypt.verify(password, result['password']):
                flash('Welcome '+result['first_name']+" "+result['last_name']+'!', 'success-login')
                session['username'] = username

                if result['photo']:
                    file_like = io.BytesIO(result['photo'])
                    photo = PIL.Image.open(file_like)
                    if result['photo_file_type'] == 'jpg':
                        photo.save(os.path.join(app.config['SAVE_FOLDER'], username+'_photo.'+result['photo_file_type']), "JPEG")
                        session['photo_path'] = url_for('static', filename='img/' + username +'_photo.'+result['photo_file_type'])
                    else:
                        photo.save(os.path.join(app.config['SAVE_FOLDER'], username+'_photo.'+result['photo_file_type']), result['photo_file_type'].upper())
                        session['photo_path'] = url_for('static', filename='img/' + username +'_photo.'+result['photo_file_type'])
                else:
                    session['photo_path'] = url_for('static', filename='img/person.png')
                if result['signature']:
                    file_like2 = io.BytesIO(result['signature'])
                    signature = PIL.Image.open(file_like2)
                    if result['signature_file_type'] == 'jpg':
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], username+'_signature.'+result['signature_file_type']), "JPEG")
                        session['signature_path'] = url_for('static', filename='img/' + username +'_signature.'+result['signature_file_type'])
                    else:
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], username+'_signature.'+result['signature_file_type']), result['signature_file_type'].upper())
                        session['signature_path'] = url_for('static', filename='img/' + username +'_signature.'+result['signature_file_type'])
                else:
                    session['signature_path'] = url_for('static', filename='img/no_signature.jpg')
                session['department'] = result['department']
                session['message'] = result['first_name']+" "+result['last_name']
                return redirect(url_for('home'))
            else:
                flash('The Password Does Not Match!', 'danger')
        else:
            flash('Not Signed up Username! Please Sign up First.', 'error')
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = {'created_date': datetime.datetime.now()}
        users['first_name'] = request.form.get('first_name')
        users['last_name'] = request.form.get('last_name')
        users['department'] = request.form.get('department')
        users['initial'] = request.form.get('initial').upper()
        users['email'] = request.form.get('email')
        users['phone'] = request.form.get('phone')
        users['username'] = request.form.get('username')
        new_password = request.form.get('password')
        confirm = request.form.get('confirm')

        result = cursor.users.find_one({"username": users['username']})

        if result:
            flash('Repeated Username! Please Try Another Username.', 'danger')
            return redirect(url_for('register'))
        else:
            if new_password == confirm:                    
                users['password'] = sha256_crypt.hash(str(request.form.get('password')))
                if 'photo' in request.files:
                    photo = request.files['photo']
                    filename1 = secure_filename(photo.filename)
                    if allowed_file(filename1):
                        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename1))
                        image = Image.open(UPLOAD_FOLDER+'/'+filename1)
                        users['photo'] = open(UPLOAD_FOLDER+'/'+filename1, 'rb').read()
                        users['photo_file_type'] = filename1.rsplit('.', 1)[1].lower()
                    else:
                        flash('Not Valid Photo File Type! (png, jpg, jpeg, gif)', 'danger')
                        return redirect(url_for('register'))
                else:
                    users['photo'] = ''
                if 'signature' in request.files:
                    signature = request.files['signature']
                    filename2 = secure_filename(signature.filename)
                    if allowed_file(filename2):
                        signature.save(os.path.join(app.config['UPLOAD_FOLDER'], filename2))
                        image2 = Image.open(UPLOAD_FOLDER+'/'+filename2)
                        users['signature'] = open(UPLOAD_FOLDER+'/'+filename2, 'rb').read()
                        users['signature_file_type'] = filename2.rsplit('.', 1)[1].lower()
                    else:
                        flash('Not Valid Signature File Type! (png, jpg, jpeg, gif)', 'danger')
                        return redirect(url_for('register'))
                else:
                    users['signature'] = ''

                cursor.users.insert_one(users)
                message = Markup("Successful Sine up! Please <a style='color:#3c763d; font-weight: bold;' href='/login'>Sign in</a>.")
                flash(message, 'success')
                return redirect(url_for('login'))
            else:
                flash('The Password Does Not Match!', 'error')
                return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/change password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current_pass = request.form.get('current_pass')
        new_pass = request.form.get('password')
        confirm = request.form.get('confirm')
        
        result = cursor.users.find_one({"username": session['username']})

        if sha256_crypt.verify(current_pass, result['password']):
            if new_pass == confirm:
                new_pass = sha256_crypt.hash(str(new_pass))
                cursor.users.update_many(
                        {"username": session['username']},
                        {'$set': {'password': new_pass}}
                        )
                flash('The Password Changed Successfuly! Please Sign in Again.', 'success-login')
                return redirect(url_for('logout'))
            else:
                flash("Didn't Match! Please Confirm New Password Again.", 'danger')
                return redirect(url_for('change_password'))
        else:
            flash('Current Password Not Matched!', 'danger')
    return render_template('index.html',
        navigator="change password",
        log_records_list=session['log_records_list']
        )

@app.route('/atc-pdf/<log_no>')
def atc_pdf(log_no):

    team_members = []
    result = cursor.log_records.find_one({"id": int(log_no)})
    for name in result['team_members']:
        team_members.append(name)

    pdfkit.from_string(render_template('includes/_forAtcPdf.html',
        result=result,
        log_records_list=session['log_records_list'],
        log_no=int(log_no),
        team_members=team_members,
        sorted_events=session['sorted_events']
        ), 'static/pdf/log number '+log_no+'.pdf')
    os.startfile('E:/AFTN-AMHS/Python/projects/Airport-Web-App/static/pdf/log number '+log_no+'.pdf')

    return render_template('index.html',
        navigator="logs",
        log_no=int(log_no),
        result=result,
        log_records_list=session['log_records_list']
        )

@app.route('/amhs-pdf/<log_no>')
def amhs_pdf(log_no):

    result = amhs_cursor.records.find_one({"id": int(log_no)})
    channel_list = ['tsa', 'sta', 'cfa', 'tia', 'mca']
    msg_list = ['fpl', 'dla', 'chg', 'notam', 'perm']
    network = ['server', 'supervisor', 'workstation', 'printer']
    msg_flag = 0
    for msg in msg_list:
        if result[msg]:
            msg_flag = 1
            break
    (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
    
    signature_path = []
    for sign in result['signature_path']:
        signature_path.append('E:/AFTN-AMHS/Python/projects/Airport-Web-App'+sign)

    pdfkit.from_string(render_template('includes/_forAmhsPdf.html',
        result=result,
        log_records_list=session['log_records_list'],
        log_no=int(log_no),
        channel_list=channel_list,
        msg_list=msg_list,
        network=network,
        msg_flag=msg_flag,
        notam_data=notam_data,
        perm_data=perm_data,
        signature_path=signature_path
        ), 'static/pdf/amhs/log number '+log_no+'.pdf')
    os.startfile('E:/AFTN-AMHS/Python/projects/Airport-Web-App/static/pdf/amhs/log number '+log_no+'.pdf')

    return redirect(url_for('amhs_log', id_no=int(log_no)))

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('datetime', None)
    session.pop('jdatetime', None)
    session.pop('current_id', None)
    session.pop('log_records_list', None)
    session.pop('username', None)
    session.pop('message', None)
    session.pop('photo_path', None)
    session.pop('signature_path', None)
    session.pop('log_no', None)
    session.pop('sorted_events', None)
    session.pop('all_members', None)
    session.pop('no_log_data_flag', None)
    session.pop('adsb_db', None)
    session.pop('statistics_flag', None)
    session.pop('metar', None)
    session.pop('department', None)
    session.pop('administration', None)


    return redirect(url_for('login'))

@app.route('/<navigator>', methods=['GET', 'POST'])
def index(navigator):
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    flt_form_list = []
    flt_scheldule_dict = {}
    wd = []
    result_count_list = []

    return render_template('index.html',
        datetime=session['datetime'],
        navigator=navigator,
        log_no=session['log_no'],
        flt_scheldule_dict=flt_scheldule_dict,
        week_days=wd,
        result_count_list=result_count_list,
        flt_form_list=flt_form_list,
        result_count=0,
        log_records_list=session['log_records_list']
        )

@app.route('/flight-schedule', methods=['GET', 'POST'])
def flight_schedule():
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    wd = []
    result_count_list = []
    flt_scheldule_dict = {}
    week_days = ['Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']

    for day in week_days:
        result_count = cursor.flights_schedule.count_documents({"week_day": day})
        result = cursor.flights_schedule.find({"week_day": day})
        if result_count:
            wd.append(day)
            result_count_list.append(result_count)
            flt_scheldule_big_list = []
            for r in result:
                flt_scheldule_list = []
                flt_scheldule_list.append(day)
                flt_scheldule_list.append(r["arr_flt_no"])
                flt_scheldule_list.append(r["dep_flt_no"])
                flt_scheldule_list.append(r["airline"])
                flt_scheldule_list.append(r["arr_from"])
                flt_scheldule_list.append(r["dep_to"])
                flt_scheldule_list.append(r["arr_time"])
                flt_scheldule_list.append(r["dep_time"])
                flt_scheldule_list.append(r["type"])
                flt_scheldule_list.append(r["id"])
                flt_scheldule_big_list.append(flt_scheldule_list)
            flt_scheldule_dict[day] = flt_scheldule_big_list

    return render_template('index.html',
        datetime=session['datetime'],
        navigator="flight-schedule",
        log_no=session['log_no'],
        flt_scheldule_dict=flt_scheldule_dict,
        week_days=wd,
        result_count_list=result_count_list,
        log_records_list=session['log_records_list']
        )

@app.route('/flight-schedule-data', methods=['GET', 'POST'])
def flights_schedule_data():
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    records = {}
    if request.method == 'POST':
        records = {}
        if cursor.flights_schedule.estimated_document_count():
            records['id'] = cursor.flights_schedule.estimated_document_count()+1
        else:
            records['id'] = 1
        records['datetime'] = datetime.datetime.utcnow()
        records['week_day'] = request.form.get('week_day')
        records['arr_flt_no'] = request.form.get('arr-flt-no')
        records['dep_flt_no'] = request.form.get('dep-flt-no')
        records['airline'] = request.form.get('airline').upper()
        records['arr_from'] = request.form.get('arr-from').upper()
        records['dep_to'] = request.form.get('dep-to').upper()
        records['arr_time'] = request.form.get('arr-time')
        records['dep_time'] = request.form.get('dep-time')
        records['type'] = request.form.get('type').upper()
        cursor.flights_schedule.insert_one(records)

    return render_template('index.html',
        datetime=session['datetime'],
        navigator="flight-schedule-data",
        log_no=session['log_no'],
        log_records_list=session['log_records_list']
        )

@app.route('/flight-form/<flight_id>', methods=['GET', 'POST'])
def flight_form(flight_id):
    print(request.base_url)
    flt_form_list = []
    flt_id = ""
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    referrer = request.headers.get("Referer")
    print(referrer)
    if ("flight-schedule" in referrer) or ("home" in referrer):
        print(referrer)
        flt_id = int(flight_id)
        result = cursor.flights_schedule.find_one({"id": flt_id})
        if result:
            print(result)
            flt_form_list.append(result["airline"])
            flt_form_list.append(result["type"])
            flt_form_list.append(result['arr_flt_no'])
            flt_form_list.append(result["arr_from"])
            flt_form_list.append(result["dep_flt_no"])
            flt_form_list.append(result["dep_to"])
            flt_form_list.append(result['week_day'])
            flt_form_list.append(result["arr_time"])
            flt_form_list.append(result["dep_time"])
    elif "fids" in referrer:
        flt_id = flight_id
        flt_form_list.append(request.args.get('airline'))
        flt_form_list.append(request.args.get('type'))
        if int(request.args.get('no')) < int(request.args.get('len'))//2:
            flt_form_list.append(request.args.get('flt_no'))
            flt_form_list.append(request.args.get('dest'))
        else:
            flt_form_list.append("")
            flt_form_list.append("")
            flt_form_list.append(request.args.get('flt_no'))
            flt_form_list.append(request.args.get('dest'))

    elif "statistics" in referrer:
        print('entered')
        session['statistics_flag'] = 1
        flt_id = int(flight_id)
        result = cursor.flights_statistics.find_one({"id": flt_id})
        if result:
            flt_form_list.append(result["airline"])
            flt_form_list.append(result["type"])
            flt_form_list.append(result['arr_flt_no'])
            flt_form_list.append(result["arr_from"])
            flt_form_list.append(result["dep_flt_no"])
            flt_form_list.append(result["dep_to"])
            flt_form_list.append(result['week_day'])
            flt_form_list.append(result["arr_time"])
            flt_form_list.append(result["dep_time"])
            flt_form_list.append(result["register"])
            flt_form_list.append(result["arr_dla_source"])
            flt_form_list.append(result["dep_dla_source"])
            flt_form_list.append(result["light"])
            flt_form_list.append(result["remarks"])
            flt_form_list.append(result["initial"])
            flt_form_list.append(result["date"])
    
    if request.method =='POST':
        print('flag= ', session['statistics_flag'])
        if session['statistics_flag']:            
            print('post')
            cursor.flights_statistics.update_many(
                {"id": int(flight_id)},
                {'$set': {
                'id': int(flight_id),
                'datetime': datetime.datetime.utcnow(),
                'airline': request.form.get('airline').upper(),
                'type': request.form.get('type').upper(),
                'register': request.form.get('reg').upper(),
                'week_day': request.form.get('week_day'),
                'arr_flt_no': request.form.get('arr-flt-no'),
                'arr_from': request.form.get('arr-from').upper(),
                'arr_time': request.form.get('arr-time'),
                'arr_dla_source': request.form.get('arr-dla'),
                'dep_flt_no': request.form.get('dep-flt-no'),
                'dep_to': request.form.get('dep-to').upper(),
                'dep_time': request.form.get('dep-time'),
                'dep_dla_source': request.form.get('dep-dla'),
                'light': request.form.get('light'),
                'remarks': request.form.get('remarks'),
                'initial': request.form.get('initial').upper()
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            session['statistics_flag'] = 0
            return redirect(url_for('statistics', airline=request.form.get('airline').upper()))

        else:
            records = {}
            if cursor.flights_statistics.estimated_document_count():
                records['id'] = cursor.flights_statistics.estimated_document_count()+1
            else:
                records['id'] = 1
            records['datetime'] = datetime.datetime.utcnow()
            records['date'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
            records['airline'] = request.form.get('airline').upper()
            records['type'] = request.form.get('type').upper()
            records['register'] = request.form.get('reg').upper()
            records['week_day'] = request.form.get('week_day')
            records['arr_flt_no'] = request.form.get('arr-flt-no')
            records['arr_from'] = request.form.get('arr-from').upper()
            records['arr_time'] = request.form.get('arr-time')
            records['arr_dla_source'] = request.form.get('arr-dla')
            records['dep_flt_no'] = request.form.get('dep-flt-no')
            records['dep_to'] = request.form.get('dep-to').upper()
            records['dep_time'] = request.form.get('dep-time')
            records['dep_dla_source'] = request.form.get('dep-dla')
            records['light'] = request.form.get('light')
            records['remarks'] = request.form.get('remarks')
            records['initial'] = request.form.get('initial').upper()
            cursor.flights_statistics.insert_one(records)
            flash('Saved Successfuly!', 'success')

    return render_template('index.html',
        datetime=session['datetime'],
        navigator='flight-form',
        flight_id=flt_id,
        flt_form_list=flt_form_list,
        flag=session['statistics_flag'],
        log_records_list=session['log_records_list']
        )

@app.route('/statistics/<airline>', methods=['GET', 'POST'])
def statistics(airline):
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    statistics_big_list = []
    result_count = cursor.flights_statistics.count_documents({"airline": airline})
    result = cursor.flights_statistics.find({"airline": airline})
    if result_count:
        for r in result:
            statistics_list = []
            statistics_list.append(r['date'])
            statistics_list.append(r['type'])
            statistics_list.append(r["arr_flt_no"])
            statistics_list.append(r["arr_from"])
            statistics_list.append(r["arr_time"])
            statistics_list.append(r["arr_dla_source"])
            statistics_list.append(r["dep_flt_no"])
            statistics_list.append(r["dep_to"])
            statistics_list.append(r["dep_time"])
            statistics_list.append(r["dep_dla_source"])
            statistics_list.append(r["light"])
            statistics_list.append(r["register"])
            statistics_list.append(r["initial"])            
            statistics_list.append(r["remarks"])
            statistics_list.append(r["id"])
            statistics_big_list.append(statistics_list)

    return render_template('index.html',
        navigator='statistics',
        airline=airline,
        statistics_big_list=statistics_big_list,
        result_count=result_count,
        log_records_list=session['log_records_list']
        )

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' in session:
        i = 1
        l = []
        result_list = []
        search_field = ""

        if request.method == 'POST':

            search_field = request.form.get('search_field')

            if request.form.get('from'):
                d_from = request.form.get('from')
                date_from = datetime.datetime.strptime(d_from, "%Y-%m-%d")
                date_from = date_from.strftime('%Y - %m - %d')
            elif request.form.get('s_from'):
                d_from = request.form.get('s_from')
                date_from = datetime.datetime.strptime(d_from, "%Y-%m-%d")
                date_from = date_from.strftime('%Y - %m - %d')
            else:
                date_from = ""

            if request.form.get('to'):
                d_to = request.form.get('to')
                date_to = datetime.datetime.strptime(d_to, "%Y-%m-%d")
                date_to = date_to.strftime('%Y - %m - %d')
            elif request.form.get('s_to'):
                d_to = request.form.get('s_to')
                date_to = datetime.datetime.strptime(d_to, "%Y-%m-%d")
                date_to = date_to.strftime('%Y - %m - %d')
            else:
                date_to = ""

            if request.form.get('initial'):
                initial = request.form.get('initial').upper()
            elif request.form.get('s_initial'):
                initial = request.form.get('s_initial').upper()
            else:
                initial = ""

            shift = request.form.get('shift')
            airline = request.form.get('s_airline')
            Type = request.form.get('s_type').upper()
            flt_no = request.form.get('s_flt_no')
            reg = request.form.get('s_reg').upper()
            arr_from = request.form.get('s_arr_from').upper()
            dep_to = request.form.get('s_dep_to').upper()

            if request.form.get('search_field') == "Logs":
                if initial or shift:
                    result = cursor.log_records.find({
                        'shift_date': {'$gte': date_from, '$lt': date_to},
                        '$or':[
                        {'shift': shift},
                        {'$or':[{'present_members': {'$elemMatch':{'$eq':initial}}}]}
                        ]
                        })
                else:
                    result = cursor.log_records.find({'shift_date': {'$gte': date_from, '$lt': date_to}})

            
            elif request.form.get('search_field') == "Flight Statistics":
                if initial or Type or flt_no or reg or arr_from or dep_to or airline:
                    result = cursor.flights_statistics.find({
                            'date': {'$gte': date_from, '$lt': date_to},
                            '$or':[{'airline': airline} , {'type': Type}, {'register': reg},
                            {'arr_from': arr_from}, {'dep_to': dep_to}, {'initial': initial},
                            {'$or':[{'arr_flt_no': flt_no}, {'dep_flt_no': flt_no}]}
                            ]
                            })
                else:
                    result = cursor.flights_statistics.find({
                            'date': {'$gte': date_from, '$lt': date_to}
                            })

            if result:
                if search_field == 'Logs':
                    for r in result:
                        l = [i, r['taken_over_from'], r['hand_over_time'], r['hand_over_to'],
                        r['team'], (", ".join(r['present_members'])), r['shift'], r['shift_date'], r['id'], "✓"]
                        result_list.append(l)
                        i = i+1
                elif search_field=='Flight Statistics':
                    for r in result:
                        l = [i, r]
                        result_list.append(l)
                        i = i+1

            else:
                flash('There is no record!', 'error')

            if not result_list:
                flash('There is no record!', 'error')

    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator="search",
        log_records_list=session['log_records_list'],
        result_list=result_list,
        search_field=search_field,
        team_members=session['all_members']
        )

@app.route('/team', methods=['GET', 'POST'])
def team():
    members = []
    if request.method == 'POST':
        records = {'datetime': datetime.datetime.utcnow()}
        records['team_number'] = request.form.get('team_number')
        for i in range(1,100):
            if request.form.get('members_initial_'+str(i)):
                members.append([request.form.get('members_name_'+str(i)), request.form.get('members_initial_'+str(i)).upper()])
        records['members'] = members
        cursor.team.insert_one(records)
        flash('Saved Successfuly!', 'success')

    return render_template('index.html',
        navigator="team",
        log_records_list=session['log_records_list']
        )

@app.route('/amhs log form', methods=['GET', 'POST'])
def amhs_log_form():
    if 'username' in session:
        result = amhs_cursor.records.find_one({"id": amhs_cursor.records.estimated_document_count()})
        wd = datetime.datetime.utcnow().weekday()
        session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
        session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
        today = session['datetime']
        if jdatetime.datetime.now().month > 6:
            A = datetime.time(3, 30)
            B = datetime.time(15, 30)
        else:
            A = datetime.time(2, 30)
            B = datetime.time(14, 30)
        if A <  datetime.datetime.utcnow().time() <= B:
            today_shift = 'Day'
            today_wd = utils.fetch_day(str(wd+1))
        elif datetime.datetime.utcnow().time() <= A:
            session['datetime'] = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
            session['jdatetime'] = (jdatetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
            today = session['datetime']
            today_shift = 'Night'
            today_wd = utils.fetch_day(str(wd))
        else:
            today_shift = 'Night'
            today_wd = utils.fetch_day(str(wd+1))
        channel_list = ['tsa', 'sta', 'cfa', 'tia', 'mca']
        msg_list = ['fpl', 'dla', 'chg', 'notam', 'perm']

        if (today==result['shift_date'] and today_shift==result['shift']):
            logdata = result
            session['log_records_list'] = utils.shift_brief(result, session['department'])
            (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
        else:
            logdata = None
            notam_data = None
            perm_data = None
            record = {'event_date': datetime.datetime.utcnow()}
            if amhs_cursor.records.estimated_document_count():
                record['id'] = amhs_cursor.records.estimated_document_count()+1
            else:
                record['id'] = 1
            record['shift_date'] = session['datetime']
            record['shift_jdate'] = session['jdatetime']
            record['on_duty'] = utils.regex(session['initial'])
            record['day'] = today_wd
            record['shift'] = today_shift
            record['team'] = ''
            record['network'] = ["server", "supervisor", "workstation", "printer"]
            for ch in channel_list:
                record[ch+'_during'] = 'OK'
                record[ch+'_end'] = 'OK'
            record['fpl'] = record['dla'] = record['chg'] = ""
            record['notam'] = record['perm'] = []
            record['signature_path']=[]
            record['signature_path'].append(session['signature_path'])
            amhs_cursor.records.insert_one(record)
            session['amhs_log_no'] = amhs_cursor.records.estimated_document_count()

        if request.method == 'POST':
            amhs_cursor.records.update_many(
                {"id": session['amhs_log_no']},
                {'$set': {
                'id': session['amhs_log_no'],
                'on_duty': utils.regex(request.form.get('on_duty').upper()),
                'shift_switch': utils.regex(request.form.get('shift_switch').upper()),
                'overtime': utils.regex(request.form.get('overtime').upper()),
                'daily_leave': utils.regex(request.form.get('daily_leave').upper()),
                'team': request.form.get('team'),
                'day': request.form.get('day'),
                'shift': request.form.get('shift'),
                'network': request.form.getlist('network'),
                'tsa_during': request.form.get('tsa_during'),
                'tsa_from': request.form.get('tsa_from'),
                'tsa_to': request.form.get('tsa_to'),
                'tsa_reason': request.form.get('tsa_reason'),
                'tsa_end': request.form.get('tsa_end'),
                'sta_during': request.form.get('sta_during'),
                'sta_from': request.form.get('sta_from'),
                'sta_to': request.form.get('sta_to'),
                'sta_reason': request.form.get('sta_reason'),
                'sta_end': request.form.get('sta_end'),
                'cfa_during': request.form.get('cfa_during'),
                'cfa_from': request.form.get('cfa_from'),
                'cfa_to': request.form.get('cfa_to'),
                'cfa_reason': request.form.get('cfa_reason'),
                'cfa_end': request.form.get('cfa_end'),
                'tia_during': request.form.get('tia_during'),
                'tia_from': request.form.get('tia_from'),
                'tia_to': request.form.get('tia_to'),
                'tia_reason': request.form.get('tia_reason'),
                'tia_end': request.form.get('tia_end'),
                'mca_during': request.form.get('mca_during'),
                'mca_from': request.form.get('mca_from'),
                'mca_to': request.form.get('mca_to'),
                'mca_reason': request.form.get('mca_reason'),
                'mca_end': request.form.get('mca_end'),
                'fpl': request.form.get('fpl'),
                'dla': request.form.get('dla'),
                'chg': request.form.get('chg'),
                'remarks': request.form.get('remarks')
                }
                }
                )
            update_signature = amhs_cursor.records.find_one({"id": session['amhs_log_no']})
            update_signature_path=[]
            od = update_signature['on_duty'] if update_signature['on_duty'][0] else []
            ov = update_signature['overtime'] if update_signature['overtime'][0] else []
            for initial in od+ov:
                signature_result = cursor.users.find_one({'initial': initial})
                if signature_result['signature']:
                    file_like = io.BytesIO(signature_result['signature'])
                    signature = PIL.Image.open(file_like)
                    if signature_result['signature_file_type'] == 'jpg':
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], signature_result['username']+'_signature.'+signature_result['signature_file_type']), "JPEG")
                        initial_signature = url_for('static', filename='img/' + signature_result['username'] +'_signature.'+signature_result['signature_file_type'])
                    else:
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], signature_result['username']+'_signature.'+signature_result['signature_file_type']), signature_result['signature_file_type'].upper())
                        initial_signature = url_for('static', filename='img/' + signature_result['username'] +'_signature.'+signature_result['signature_file_type'])
                else:
                    initial_signature = url_for('static', filename='img/no_signature.jpg')
                update_signature_path.append(initial_signature)

            amhs_cursor.records.update_many(
                    {"id": session['amhs_log_no']},
                    {'$set': {'signature_path': update_signature_path}}
                    )
            flash('Saved Successfuly!', 'success')
            if not session['log_records_list']:
                result = amhs_cursor.records.find_one({"id": session['amhs_log_no']})
                session['log_records_list'] = utils.shift_brief(result, session['department'])
            return redirect(url_for('amhs_log_form'))


    return render_template('index.html',
        navigator="amhs log form",
        log_no=session['amhs_log_no'],
        wd=today_wd,
        result = logdata,
        today_shift=today_shift,
        channel_list=channel_list,
        msg_list=msg_list,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data
        )

@app.route('/amhs logs/<id_no>', methods=['GET', 'POST'])
def amhs_log(id_no):
    if 'username' in session:
        result = amhs_cursor.records.find_one({"id": int(id_no)})
        channel_list = ['tsa', 'sta', 'cfa', 'tia', 'mca']
        msg_list = ['fpl', 'dla', 'chg', 'notam', 'perm']
        network = ['server', 'supervisor', 'workstation', 'printer']
        msg_flag = 0
        for msg in msg_list:
            if result[msg]:
                msg_flag = 1
                break
        (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)


    return render_template('index.html',
        navigator="amhs logs",
        log_no=int(id_no),
        result = result,
        channel_list=channel_list,
        msg_list=msg_list,
        msg_flag=msg_flag,
        network=network,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data
        )

@app.route('/amhs logs/<id_no>/edit', methods=['GET', 'POST'])
def edit_amhs_log(id_no):
    if 'username' in session:
        result = amhs_cursor.records.find_one({"id": int(id_no)})
        channel_list = ['tsa', 'sta', 'cfa', 'tia', 'mca']
        msg_list = ['fpl', 'dla', 'chg', 'notam', 'perm']
        network = ['server', 'supervisor', 'workstation', 'printer']
        (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
        if request.method == 'POST':
            amhs_cursor.records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'on_duty': utils.regex(request.form.get('on_duty').upper()),
                'shift_switch': utils.regex(request.form.get('shift_switch').upper()),
                'overtime': utils.regex(request.form.get('overtime').upper()),
                'daily_leave': utils.regex(request.form.get('daily_leave').upper()),
                'team': request.form.get('team'),
                'day': request.form.get('day'),
                'shift': request.form.get('shift'),
                'network': request.form.getlist('network'),
                'tsa_during': request.form.get('tsa_during'),
                'tsa_from': request.form.get('tsa_from'),
                'tsa_to': request.form.get('tsa_to'),
                'tsa_reason': request.form.get('tsa_reason'),
                'tsa_end': request.form.get('tsa_end'),
                'sta_during': request.form.get('sta_during'),
                'sta_from': request.form.get('sta_from'),
                'sta_to': request.form.get('sta_to'),
                'sta_reason': request.form.get('sta_reason'),
                'sta_end': request.form.get('sta_end'),
                'cfa_during': request.form.get('cfa_during'),
                'cfa_from': request.form.get('cfa_from'),
                'cfa_to': request.form.get('cfa_to'),
                'cfa_reason': request.form.get('cfa_reason'),
                'cfa_end': request.form.get('cfa_end'),
                'tia_during': request.form.get('tia_during'),
                'tia_from': request.form.get('tia_from'),
                'tia_to': request.form.get('tia_to'),
                'tia_reason': request.form.get('tia_reason'),
                'tia_end': request.form.get('tia_end'),
                'mca_during': request.form.get('mca_during'),
                'mca_from': request.form.get('mca_from'),
                'mca_to': request.form.get('mca_to'),
                'mca_reason': request.form.get('mca_reason'),
                'mca_end': request.form.get('mca_end'),
                'fpl': request.form.get('fpl'),
                'dla': request.form.get('dla'),
                'chg': request.form.get('chg'),
                'remarks': request.form.get('remarks')
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('amhs_log', id_no=int(id_no)))

    return render_template('index.html',
        navigator="edit amhs logs",
        log_no=int(id_no),
        result = result,
        channel_list=channel_list,
        msg_list=msg_list,
        network=network,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data
        )

@app.route('/duty', methods=['GET', 'POST'])
def duty():
    if 'username' in session:
        each_team_members = {}
        for i in range (1,6):
            each_team = cursor.team.find_one({'team_number':str(i)})
            each_team_members[i] = each_team['members']

        wd = datetime.datetime.utcnow().weekday()

        on_duty_description = {'name':[], 'status':[], 'shift_switch':[], 'description':[]}

        session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
        session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
        session['current_id'] = cursor.log_records.estimated_document_count()
        session['log_no'] = session['current_id']
        today = session['datetime']

        if jdatetime.datetime.now().month > 6:
            A = datetime.time(3, 30)
            B = datetime.time(15, 30)
        else:
            A = datetime.time(2, 30)
            B = datetime.time(14, 30)

        if A <  datetime.datetime.utcnow().time() <= B:
            today_shift = 'Day'
            today_wd = utils.fetch_day(str(wd+1))
        elif datetime.datetime.utcnow().time() <= A:
            session['datetime'] = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
            session['jdatetime'] = (jdatetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y - %m - %d')
            today = session['datetime']
            today_shift = 'Night'
            today_wd = utils.fetch_day(str(wd))
        else:
            today_shift = 'Night'
            today_wd = utils.fetch_day(str(wd+1))
        
        records = {}
        if cursor.log_records.estimated_document_count():
            result = cursor.log_records.find_one({"id": cursor.log_records.estimated_document_count()})
            taken_over_from = result["hand_over_to"]
            records['id'] = cursor.log_records.estimated_document_count()+1
        else:
            result = {'shift_date':(datetime.datetime.utcnow() - datetime.timedelta(days=10)).strftime('%Y - %m - %d'), 'shift':''}
            taken_over_from = "-"
            records['id'] = 1

        if today==result['shift_date'] and today_shift==result['shift']:
            session['log_data_flag'] = 1
            return redirect(url_for('logs_duty', id_no=(session['current_id'])))

        if request.method == 'POST':
            for i in range (1,100):
                if request.form.get('name_'+str(i)):
                    on_duty_description['name'].append([
                        utils.name_related_initial(request.form.get('name_'+str(i)), session['all_members']),
                        request.form.get('name_'+str(i))
                        ])
                    on_duty_description['status'].append(request.form.get('duty_status_'+str(i)))
                    on_duty_description['shift_switch'].append([
                        utils.name_related_initial(request.form.get('shift_switch_'+str(i)), session['all_members']),
                        request.form.get('shift_switch_'+str(i))
                        ])
                    on_duty_description['description'].append(request.form.get('duty_description_'+str(i)))

            team_result = cursor.team.find_one({"team_number": request.form.get('team')})
            mem = []
            for init in request.form.getlist('present_members'):
                for item in session['all_members']:
                    if init in item:
                        mem.append(item)
            members = mem

            records['datetime'] = datetime.datetime.utcnow()
            records['taken_over_from'] = taken_over_from
            records['shift_date'] = session['datetime']
            records['shift_jdate'] = session['jdatetime']
            records['hand_over_time'] = datetime.datetime.utcnow().strftime('%H : %M')
            records['hand_over_to'] = request.form.get('hand_over_to').upper()
            records['rwy_in_use'] = request.form.get('rwy_in_use')
            records['team_members'] = members
            records['team'] = request.form.get('team')
            records['present_members'] = request.form.getlist('present_members')
            records['on_duty_description'] = on_duty_description
            records['week_day'] = request.form.get('week_day')
            records['shift'] = request.form.get('shift')
            records['inspection_time'] = request.form.get('inspection_time')
            records['inspector'] = request.form.get('inspector').upper()
            records['inspection_result'] = request.form.get('inspection_result')
            cursor.log_records.insert_one(records)
            session['filled_log_data_flag'] = 0
            session['log_data_flag'] = 1
            session['current_id'] = cursor.log_records.estimated_document_count()
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('logs_duty', id_no=(cursor.log_records.estimated_document_count())))            

    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator="duty",
        datetime=session['datetime'],
        jdatetime=session['jdatetime'],
        taken_over_from=taken_over_from,
        hand_over_time=datetime.datetime.utcnow().strftime('%H : %M'),
        log_records_list=session['log_records_list'],
        wd=today_wd,
        today_shift=today_shift,
        team_members=session['all_members'],
        each_team_members=each_team_members,
        result=None
        )

@app.route('/duty/<id_no>', methods=['GET', 'POST'])
def logs_duty(id_no):
    if 'username' in session:
        session['log_no'] = cursor.log_records.estimated_document_count()
        team_members = []
        result = cursor.log_records.find_one({"id": int(id_no)})
        for name in result['team_members']:
            team_members.append(name)

        each_team_members = {}
        for i in range (1,6):
            each_team = cursor.team.find_one({'team_number':str(i)})
            each_team_members[i] = each_team['members']

        on_duty_description = {'name':[], 'status':[], 'shift_switch':[], 'description':[]}
        result = cursor.log_records.find_one({"id": int(id_no)})
        if int(id_no) == session['current_id']:
            session['log_records_list'] = utils.shift_brief(result, session['department'])
        #cursor.log_records.insert_one(records)

        if request.method == 'POST':
            for i in range (1,100):
                if request.form.get('name_'+str(i)):
                    on_duty_description['name'].append([
                        utils.name_related_initial(request.form.get('name_'+str(i)), session['all_members']),
                        request.form.get('name_'+str(i))
                        ])
                    on_duty_description['status'].append(request.form.get('duty_status_'+str(i)))
                    on_duty_description['shift_switch'].append([
                        utils.name_related_initial(request.form.get('shift_switch_'+str(i)), session['all_members']),
                        request.form.get('shift_switch_'+str(i))
                        ])
                    on_duty_description['description'].append(request.form.get('duty_description_'+str(i)))

            team_result = cursor.team.find_one({"team_number": request.form.get('team')})
            mem = []
            for item in team_result['members']:
                mem.append(item[1])
            if request.form.get('if_all_team_members') == 'Yes':
                members = mem
            else:
                pass;

            cursor.log_records.update_many(
                    {"id": int(id_no)},
                    {'$set': {
                    'id': int(id_no),
                    'datetime': datetime.datetime.utcnow(),
                    'hand_over_to': request.form.get('hand_over_to').upper(),
                    'rwy_in_use': request.form.get('rwy_in_use'),
                    'team': request.form.get('team'),
                    #'team_members': members,
                    'present_members': request.form.getlist('present_members'),
                    'on_duty_description': on_duty_description,
                    'week_day': request.form.get('week_day'),
                    'shift': request.form.get('shift'),
                    'inspection_time': request.form.get('inspection_time'),
                    'inspector': request.form.get('inspector').upper(),
                    'inspection_result': request.form.get('inspection_result')
                    }
                    }
                    )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('logs_duty', id_no=int(id_no)))

    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator="duty",
        datetime=session['datetime'],
        result=result,
        jdatetime=session['jdatetime'],
        taken_over_from=result['taken_over_from'],
        hand_over_time=result['hand_over_time'],
        log_records_list=session['log_records_list'],
        team_members=session['all_members'],
        each_team_members=each_team_members
        )

@app.route('/log data', methods=['GET', 'POST'])
def logs_data():
    if 'username' in session:
        if session['log_data_flag']:
            largest_len = 0
            first_list = []
            last_list = []
            if session['filled_log_data_flag']:
                result = cursor.log_records.find_one({"id": session['current_id']})
                navigator = 'filled log data'
                largest_len = (len(result['event_com']['title']) + len(result['event_nav']['title']) +
                    len(result['event_sur']['title']) + len(result['event_rwy_twy']['title']) +
                    len(result['event_lgt']['title']) + len(result['event_eqp']['title']) +
                    len(result['event_rwy_in_use']['text']) + len(result['event_rwy_inspection']['inspector']) +
                    len(result['event_rpv']['call_sign']) + len(result['event_other']['title']))

                if len(result['com_title']):
                    first_list.append('logdata/_comFull.html')
                else:
                    last_list.append('logdata/_comNull.html')
                if len(result['nav_title']):
                    first_list.append('logdata/_navFull.html')
                else:
                    last_list.append('logdata/_navNull.html')
                if len(result['sur_title']):
                    first_list.append('logdata/_surFull.html')
                else:
                    last_list.append('logdata/_surNull.html')
                if len(result['rwy_twy_title']):
                    first_list.append('logdata/_rwy_twyFull.html')
                else:
                    last_list.append('logdata/_rwy_twyNull.html')
                if len(result['lgt_title']):
                    first_list.append('logdata/_lgtFull.html')
                else:
                    last_list.append('logdata/_lgtNull.html')
                if len(result['eqp_title']):
                    first_list.append('logdata/_eqpFull.html')
                else:
                    last_list.append('logdata/_eqpNull.html')
                if (result['event_com']['title']==[] and result['event_nav']['title']==[] and result['event_sur']['title']==[]
                        and result['event_rwy_twy']['title']==[] and result['event_lgt']['title']==[] and result['event_eqp']['title']==[]
                        and result['event_rwy_in_use']['text']==[] and result['event_rwy_inspection']['inspector']==[]
                        and result['event_rpv']['call_sign']==[] and result['event_other']['title']==[]):
                        last_list.append('logdata/_eventNull.html')
                else:
                    first_list.append('logdata/_eventFull.html')
                    last_list.insert(0, 'logdata/_eventNull.html')
            else:
                navigator = 'log data'
                print(session['current_id'])
                result = cursor.log_records.find_one({"id": session['current_id']})

            log_records_list = []
            com_title_list = []
            com_status_list = []
            com_description_list = []
            nav_title_list = []
            nav_status_list = []
            nav_description_list = []
            sur_title_list = []
            sur_status_list = []
            sur_description_list = []
            rwy_twy_title_list = []
            rwy_twy_status_list = []
            rwy_twy_description_list = []
            lgt_title_list = []
            lgt_status_list = []
            lgt_description_list = []
            eqp_title_list = []
            eqp_status_list = []
            eqp_description_list = []
            event_com = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_nav = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_sur = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_rwy_twy = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_lgt = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_eqp = {'title':[], 'status':[], 'time':[], 'reason':[]}
            event_rwy_in_use = {'text':[], 'time':[], 'reason':[]}
            event_rwy_inspection = {'inspector':[], 'time':[], 'reason':[]}
            event_rpv = {'call_sign':[], 'takeoff_time':[], 'landing_time':[], 'reason':[], 'description':[]}
            event_other = {'title':[], 'time':[], 'reason':[]}


            if request.method == 'POST':
                for i in range (100):
                    if request.form.get('com_title_'+str(i)):
                        com_title_list.append(request.form.get('com_title_'+str(i)))
                        com_status_list.append(request.form.get('com_status_'+str(i)))
                        com_description_list.append(request.form.get('com_description_'+str(i)))

                for j in range(100):
                    if request.form.get('nav_title_'+str(j)):
                        nav_title_list.append(request.form.get('nav_title_'+str(j)))
                        nav_status_list.append(request.form.get('nav_status_'+str(j)))
                        nav_description_list.append(request.form.get('nav_description_'+str(j)))

                for k in range(100):
                    if request.form.get('sur_title_'+str(k)):
                        sur_title_list.append(request.form.get('sur_title_'+str(k)))
                        sur_status_list.append(request.form.get('sur_status_'+str(k)))
                        sur_description_list.append(request.form.get('sur_description_'+str(k)))

                for l in range(100):
                    if request.form.get('rwy_twy_title_'+str(l)):
                        rwy_twy_title_list.append(request.form.get('rwy_twy_title_'+str(l)))
                        rwy_twy_status_list.append(request.form.get('rwy_twy_status_'+str(l)))
                        rwy_twy_description_list.append(request.form.get('rwy_twy_description_'+str(l)))

                for m in range(100):
                    if request.form.get('lgt_title_'+str(m)):
                        lgt_title_list.append(request.form.get('lgt_title_'+str(m)))
                        lgt_status_list.append(request.form.get('lgt_status_'+str(m)))
                        lgt_description_list.append(request.form.get('lgt_description_'+str(m)))

                for n in range(100):
                    if request.form.get('eqp_title_'+str(n)):
                        eqp_title_list.append(request.form.get('eqp_title_'+str(n)))
                        eqp_status_list.append(request.form.get('eqp_status_'+str(n)))
                        eqp_description_list.append(request.form.get('eqp_description_'+str(n)))

                for o in range(100):
                    if request.form.get('event_title_'+str(o)):
                        if request.form.get('event_title_'+str(o)) == "Communication":
                            event_com['title'].append(request.form.get('ev_'+str(o)+'_com_title'))
                            event_com['status'].append(request.form.get('ev_'+str(o)+'_com_status'))
                            event_com['time'].append(request.form.get('ev_'+str(o)+'_com_time'))
                            event_com['reason'].append(request.form.get('ev_'+str(o)+'_com_reason'))
                        if request.form.get('event_title_'+str(o)) == "Navigation":
                            event_nav['title'].append(request.form.get('ev_'+str(o)+'_nav_title'))
                            event_nav['status'].append(request.form.get('ev_'+str(o)+'_nav_status'))
                            event_nav['time'].append(request.form.get('ev_'+str(o)+'_nav_time'))
                            event_nav['reason'].append(request.form.get('ev_'+str(o)+'_nav_reason'))
                        if request.form.get('event_title_'+str(o)) == "Surveillance":
                            event_sur['title'].append(request.form.get('ev_'+str(o)+'_sur_title'))
                            event_sur['status'].append(request.form.get('ev_'+str(o)+'_sur_status'))
                            event_sur['time'].append(request.form.get('ev_'+str(o)+'_sur_time'))
                            event_sur['reason'].append(request.form.get('ev_'+str(o)+'_sur_reason'))
                        if request.form.get('event_title_'+str(o)) == "RWY TWY":
                            event_rwy_twy['title'].append(request.form.get('ev_'+str(o)+'_rwy_twy_title'))
                            event_rwy_twy['status'].append(request.form.get('ev_'+str(o)+'_rwy_twy_status'))
                            event_rwy_twy['time'].append(request.form.get('ev_'+str(o)+'_rwy_twy_time'))
                            event_rwy_twy['reason'].append(request.form.get('ev_'+str(o)+'_rwy_twy_reason'))
                        if request.form.get('event_title_'+str(o)) == "Lights":
                            event_lgt['title'].append(request.form.get('ev_'+str(o)+'_lgt_title'))
                            event_lgt['status'].append(request.form.get('ev_'+str(o)+'_lgt_status'))
                            event_lgt['time'].append(request.form.get('ev_'+str(o)+'_lgt_time'))
                            event_lgt['reason'].append(request.form.get('ev_'+str(o)+'_lgt_reason'))
                        if request.form.get('event_title_'+str(o)) == "Equipments":
                            event_eqp['title'].append(request.form.get('ev_'+str(o)+'_eqp_title'))
                            event_eqp['status'].append(request.form.get('ev_'+str(o)+'_eqp_status'))
                            event_eqp['time'].append(request.form.get('ev_'+str(o)+'_eqp_time'))
                            event_eqp['reason'].append(request.form.get('ev_'+str(o)+'_eqp_reason'))
                        if request.form.get('event_title_'+str(o)) == "RWY in Use":
                            event_rwy_in_use['text'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_text'))
                            event_rwy_in_use['time'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_time'))
                            event_rwy_in_use['reason'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_reason'))
                        if request.form.get('event_title_'+str(o)) == "RWY Inspection":
                            event_rwy_inspection['inspector'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_inspector'))
                            event_rwy_inspection['time'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_time'))
                            event_rwy_inspection['reason'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_reason'))
                        if request.form.get('event_title_'+str(o)) == "RPV":
                            event_rpv['call_sign'].append(request.form.get('ev_'+str(o)+'_rpv_call_sign'))
                            event_rpv['takeoff_time'].append(request.form.get('ev_'+str(o)+'_rpv_takeoff_time'))
                            event_rpv['landing_time'].append(request.form.get('ev_'+str(o)+'_rpv_landing_time'))
                            event_rpv['reason'].append(request.form.get('ev_'+str(o)+'_rpv_reason'))
                            event_rpv['description'].append(request.form.get('ev_'+str(o)+'_rpv_description'))
                        if request.form.get('event_title_'+str(o)) == "Other":
                            event_other['title'].append(request.form.get('ev_'+str(o)+'_other_title'))
                            event_other['time'].append(request.form.get('ev_'+str(o)+'_other_time'))
                            event_other['reason'].append(request.form.get('ev_'+str(o)+'_other_reason'))

                cursor.log_records.update_many(
                    {"id": cursor.log_records.estimated_document_count()},
                    {'$set': {
                    'id': cursor.log_records.estimated_document_count(),
                    'com_title': com_title_list,
                    'com_status': com_status_list,
                    'com_description': com_description_list,
                    'nav_title': nav_title_list,
                    'nav_status': nav_status_list,
                    'nav_description': nav_description_list,
                    'sur_title': sur_title_list,
                    'sur_status': sur_status_list,
                    'sur_description': sur_description_list,
                    'rwy_twy_title': rwy_twy_title_list,
                    'rwy_twy_status': rwy_twy_status_list,
                    'rwy_twy_description': rwy_twy_description_list,
                    'lgt_title': lgt_title_list,
                    'lgt_status': lgt_status_list,
                    'lgt_description': lgt_description_list,
                    'eqp_title': eqp_title_list,
                    'eqp_status': eqp_status_list,
                    'eqp_description': eqp_description_list,
                    'event_com': event_com,
                    'event_nav': event_nav,
                    'event_sur': event_sur,
                    'event_rwy_twy': event_rwy_twy,
                    'event_lgt': event_lgt,
                    'event_eqp': event_eqp,
                    'event_rwy_in_use': event_rwy_in_use,
                    'event_rwy_inspection': event_rwy_inspection,
                    'event_rpv': event_rpv,
                    'event_other': event_other
                    }
                    }
                    )
                session['filled_log_data_flag'] = 1
                flash('Saved Successfuly!', 'success')
                return redirect(url_for('logs_data'))                

        else:
            message = Markup("Please Fill The <a style='color:#8a6d3b; font-weight:bold;' href='/duty' Title='On-Duty Info'>On-Duty Information Form</a> First!")
            flash(message, 'error')
            return redirect(request.referrer)
    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator=navigator,
        log_records_list=session['log_records_list'],
        result=result,
        first_list=first_list,
        last_list=last_list,
        counter=largest_len+1
        )

@app.route('/logs/<log_no>', methods=['GET', 'POST'])
def logs(log_no):
    if 'username' in session:
        print(session['filled_log_data_flag'])
        sorted_events = []
        result = cursor.log_records.find_one({"id": int(log_no)})
        if 'com_title' in result.keys():
            session['no_log_data_flag'] = 0
            session['filled_log_data_flag'] = 1
        else:
            session['no_log_data_flag'] = 1
            session['filled_log_data_flag'] = 0

        if session['filled_log_data_flag']:
            events = [result['event_com']['time'], result['event_nav']['time'],
            result['event_sur']['time'], result['event_rwy_twy']['time'], result['event_lgt']['time'],
            result['event_eqp']['time'], result['event_rwy_in_use']['time'],
            result['event_rwy_inspection']['time'], result['event_other']['time']]
            for item in events:
                for time in item:
                    sorted_events.append([time, events.index(item)])
            sorted_events.sort()
            for item in sorted_events:
                if item[1]==0: sorted_events[sorted_events.index(item)] = ['com', result['event_com'], result['event_com']['time'].index(item[0])]
                elif item[1]==1: sorted_events[sorted_events.index(item)] = ['nav', result['event_nav'], result['event_nav']['time'].index(item[0])]
                elif item[1]==2: sorted_events[sorted_events.index(item)] = ['sur', result['event_sur'], result['event_sur']['time'].index(item[0])]
                elif item[1]==3: sorted_events[sorted_events.index(item)] = ['rwy_twy', result['event_rwy_twy'], result['event_rwy_twy']['time'].index(item[0])]
                elif item[1]==4: sorted_events[sorted_events.index(item)] = ['lgt', result['event_lgt'], result['event_lgt']['time'].index(item[0])]
                elif item[1]==5: sorted_events[sorted_events.index(item)] = ['eqp', result['event_eqp'], result['event_eqp']['time'].index(item[0])]
                elif item[1]==6: sorted_events[sorted_events.index(item)] = ['rwy_in_use', result['event_rwy_in_use'], result['event_rwy_in_use']['time'].index(item[0])]
                elif item[1]==7: sorted_events[sorted_events.index(item)] = ['rwy_inspection', result['event_rwy_inspection'], result['event_rwy_inspection']['time'].index(item[0])]
                elif item[1]==8: sorted_events[sorted_events.index(item)] = ['other', result['event_other'], result['event_other']['time'].index(item[0])]
            session['sorted_events'] = sorted_events

    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator="logs",
        log_no=int(log_no),
        result=result,
        log_records_list=session['log_records_list'],
        sorted_events=sorted_events
        )

@app.route('/logs/<log_no>/edit', methods=['GET', 'POST'])
def edit_log(log_no):
    if 'username' in session:
        largest_len = 0
        first_list = []
        last_list = []
        result = cursor.log_records.find_one({"id": int(log_no)})
        if not session['no_log_data_flag']:
            largest_len = (len(result['event_com']['title']) + len(result['event_nav']['title']) +
                len(result['event_sur']['title']) + len(result['event_rwy_twy']['title']) +
                len(result['event_lgt']['title']) + len(result['event_eqp']['title']) +
                len(result['event_rwy_in_use']['text']) + len(result['event_rwy_inspection']['inspector']) +
                len(result['event_rpv']['call_sign']) + len(result['event_other']['title']))

            if len(result['com_title']):
                first_list.append('logdata/_comFull.html')
            else:
                last_list.append('logdata/_comNull.html')
            if len(result['nav_title']):
                first_list.append('logdata/_navFull.html')
            else:
                last_list.append('logdata/_navNull.html')
            if len(result['sur_title']):
                first_list.append('logdata/_surFull.html')
            else:
                last_list.append('logdata/_surNull.html')
            if len(result['rwy_twy_title']):
                first_list.append('logdata/_rwy_twyFull.html')
            else:
                last_list.append('logdata/_rwy_twyNull.html')
            if len(result['lgt_title']):
                first_list.append('logdata/_lgtFull.html')
            else:
                last_list.append('logdata/_lgtNull.html')
            if len(result['eqp_title']):
                first_list.append('logdata/_eqpFull.html')
            else:
                last_list.append('logdata/_eqpNull.html')
            if (result['event_com']['title']==[] and result['event_nav']['title']==[] and result['event_sur']['title']==[]
                and result['event_rwy_twy']['title']==[] and result['event_lgt']['title']==[] and result['event_eqp']['title']==[]
                and result['event_rwy_in_use']['text']==[] and result['event_rwy_inspection']['inspector']==[]
                and result['event_rpv']['call_sign']==[] and result['event_other']['title']==[]):
                last_list.append('logdata/_eventNull.html')
            else:
                first_list.append('logdata/_eventFull.html')
                last_list.insert(0, 'logdata/_eventNull.html')
        else:
            last_list.append('logdata/_comNull.html')
            last_list.append('logdata/_navNull.html')
            last_list.append('logdata/_surNull.html')
            last_list.append('logdata/_rwy_twyNull.html')
            last_list.append('logdata/_lgtNull.html')
            last_list.append('logdata/_eqpNull.html')
            last_list.append('logdata/_eventNull.html')

        com_title_list = []
        com_status_list = []
        com_description_list = []
        nav_title_list = []
        nav_status_list = []
        nav_description_list = []
        sur_title_list = []
        sur_status_list = []
        sur_description_list = []
        rwy_twy_title_list = []
        rwy_twy_status_list = []
        rwy_twy_description_list = []
        lgt_title_list = []
        lgt_status_list = []
        lgt_description_list = []
        eqp_title_list = []
        eqp_status_list = []
        eqp_description_list = []
        event_com = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_nav = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_sur = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_rwy_twy = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_lgt = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_eqp = {'title':[], 'status':[], 'time':[], 'reason':[]}
        event_rwy_in_use = {'text':[], 'time':[], 'reason':[]}
        event_rwy_inspection = {'inspector':[], 'time':[], 'reason':[]}
        event_rpv = {'call_sign':[], 'takeoff_time':[], 'landing_time':[], 'reason':[], 'description':[]}
        event_other = {'title':[], 'time':[], 'reason':[]}
        on_duty_description = {'name':[], 'status':[], 'shift_switch':[], 'description':[]}

        if request.method == 'POST':
            for i in range (100):
                if request.form.get('com_title_'+str(i)):
                    com_title_list.append(request.form.get('com_title_'+str(i)))
                    com_status_list.append(request.form.get('com_status_'+str(i)))
                    com_description_list.append(request.form.get('com_description_'+str(i)))

            for j in range(100):
                if request.form.get('nav_title_'+str(j)):
                    nav_title_list.append(request.form.get('nav_title_'+str(j)))
                    nav_status_list.append(request.form.get('nav_status_'+str(j)))
                    nav_description_list.append(request.form.get('nav_description_'+str(j)))

            for k in range(100):
                if request.form.get('sur_title_'+str(k)):
                    sur_title_list.append(request.form.get('sur_title_'+str(k)))
                    sur_status_list.append(request.form.get('sur_status_'+str(k)))
                    sur_description_list.append(request.form.get('sur_description_'+str(k)))

            for l in range(100):
                if request.form.get('rwy_twy_title_'+str(l)):
                    rwy_twy_title_list.append(request.form.get('rwy_twy_title_'+str(l)))
                    rwy_twy_status_list.append(request.form.get('rwy_twy_status_'+str(l)))
                    rwy_twy_description_list.append(request.form.get('rwy_twy_description_'+str(l)))

            for m in range(100):
                if request.form.get('lgt_title_'+str(m)):
                    lgt_title_list.append(request.form.get('lgt_title_'+str(m)))
                    lgt_status_list.append(request.form.get('lgt_status_'+str(m)))
                    lgt_description_list.append(request.form.get('lgt_description_'+str(m)))

            for n in range(100):
                if request.form.get('eqp_title_'+str(n)):
                    eqp_title_list.append(request.form.get('eqp_title_'+str(n)))
                    eqp_status_list.append(request.form.get('eqp_status_'+str(n)))
                    eqp_description_list.append(request.form.get('eqp_description_'+str(n)))

            for o in range(100):
                if request.form.get('event_title_'+str(o)):
                    if request.form.get('event_title_'+str(o)) == "Communication":
                        event_com['title'].append(request.form.get('ev_'+str(o)+'_com_title'))
                        event_com['status'].append(request.form.get('ev_'+str(o)+'_com_status'))
                        event_com['time'].append(request.form.get('ev_'+str(o)+'_com_time'))
                        event_com['reason'].append(request.form.get('ev_'+str(o)+'_com_reason'))
                    if request.form.get('event_title_'+str(o)) == "Navigation":
                        event_nav['title'].append(request.form.get('ev_'+str(o)+'_nav_title'))
                        event_nav['status'].append(request.form.get('ev_'+str(o)+'_nav_status'))
                        event_nav['time'].append(request.form.get('ev_'+str(o)+'_nav_time'))
                        event_nav['reason'].append(request.form.get('ev_'+str(o)+'_nav_reason'))
                    if request.form.get('event_title_'+str(o)) == "Surveillance":
                        event_sur['title'].append(request.form.get('ev_'+str(o)+'_sur_title'))
                        event_sur['status'].append(request.form.get('ev_'+str(o)+'_sur_status'))
                        event_sur['time'].append(request.form.get('ev_'+str(o)+'_sur_time'))
                        event_sur['reason'].append(request.form.get('ev_'+str(o)+'_sur_reason'))
                    if request.form.get('event_title_'+str(o)) == "RWY TWY":
                        event_rwy_twy['title'].append(request.form.get('ev_'+str(o)+'_rwy_twy_title'))
                        event_rwy_twy['status'].append(request.form.get('ev_'+str(o)+'_rwy_twy_status'))
                        event_rwy_twy['time'].append(request.form.get('ev_'+str(o)+'_rwy_twy_time'))
                        event_rwy_twy['reason'].append(request.form.get('ev_'+str(o)+'_rwy_twy_reason'))
                    if request.form.get('event_title_'+str(o)) == "Lights":
                        event_lgt['title'].append(request.form.get('ev_'+str(o)+'_lgt_title'))
                        event_lgt['status'].append(request.form.get('ev_'+str(o)+'_lgt_status'))
                        event_lgt['time'].append(request.form.get('ev_'+str(o)+'_lgt_time'))
                        event_lgt['reason'].append(request.form.get('ev_'+str(o)+'_lgt_reason'))
                    if request.form.get('event_title_'+str(o)) == "Equipments":
                        event_eqp['title'].append(request.form.get('ev_'+str(o)+'_eqp_title'))
                        event_eqp['status'].append(request.form.get('ev_'+str(o)+'_eqp_status'))
                        event_eqp['time'].append(request.form.get('ev_'+str(o)+'_eqp_time'))
                        event_eqp['reason'].append(request.form.get('ev_'+str(o)+'_eqp_reason'))
                    if request.form.get('event_title_'+str(o)) == "RWY in Use":
                        event_rwy_in_use['text'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_text'))
                        event_rwy_in_use['time'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_time'))
                        event_rwy_in_use['reason'].append(request.form.get('ev_'+str(o)+'_rwy-in-use_reason'))
                    if request.form.get('event_title_'+str(o)) == "RWY Inspection":
                        event_rwy_inspection['inspector'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_inspector'))
                        event_rwy_inspection['time'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_time'))
                        event_rwy_inspection['reason'].append(request.form.get('ev_'+str(o)+'_rwy-inspection_reason'))
                    if request.form.get('event_title_'+str(o)) == "RPV":
                        event_rpv['call_sign'].append(request.form.get('ev_'+str(o)+'_rpv_call_sign'))
                        event_rpv['takeoff_time'].append(request.form.get('ev_'+str(o)+'_rpv_takeoff_time'))
                        event_rpv['landing_time'].append(request.form.get('ev_'+str(o)+'_rpv_landing_time'))
                        event_rpv['reason'].append(request.form.get('ev_'+str(o)+'_rpv_reason'))
                        event_rpv['description'].append(request.form.get('ev_'+str(o)+'_rpv_description'))
                    if request.form.get('event_title_'+str(o)) == "Other":
                        event_other['title'].append(request.form.get('ev_'+str(o)+'_other_title'))
                        event_other['time'].append(request.form.get('ev_'+str(o)+'_other_time'))
                        event_other['reason'].append(request.form.get('ev_'+str(o)+'_other_reason'))

            for p in range (100):
                if request.form.get('name_'+str(p)):
                    on_duty_description['name'].append([
                        utils.name_related_initial(request.form.get('name_'+str(p)), session['all_members']),
                        request.form.get('name_'+str(p))
                        ])
                    on_duty_description['status'].append(request.form.get('duty_status_'+str(p)))
                    on_duty_description['shift_switch'].append([
                        utils.name_related_initial(request.form.get('shift_switch_'+str(p)), session['all_members']),
                        request.form.get('shift_switch_'+str(p))
                        ])
                    on_duty_description['description'].append(request.form.get('duty_description_'+str(p)))

            team_result = cursor.team.find_one({"team_number": request.form.get('team')})
            mem = []
            for item in session['all_members']:
                print(item)
                for init in utils.regex(request.form.get('present_members').upper()):
                    print("init:", init)
                    if init == item[1]:
                        mem.append(item)
            members = mem

            cursor.log_records.update_many(
                {"id": int(log_no)},
                {'$set': {
                'id': int(log_no),
                'datetime': datetime.datetime.utcnow(),
                'hand_over_to': request.form.get('hand_over_to').upper(),
                'rwy_in_use': request.form.get('rwy_in_use'),
                'team': request.form.get('team'),
                'team_members': members,
                'present_members': utils.regex(request.form.get('present_members').upper()),
                'on_duty_description': on_duty_description,
                'week_day': request.form.get('week_day'),
                'shift': request.form.get('shift'),
                'inspection_time': request.form.get('inspection_time'),
                'inspector': request.form.get('inspector').upper(),
                'inspection_result': request.form.get('inspection_result'),
                'com_title': com_title_list,
                'com_status': com_status_list,
                'com_description': com_description_list,
                'nav_title': nav_title_list,
                'nav_status': nav_status_list,
                'nav_description': nav_description_list,
                'sur_title': sur_title_list,
                'sur_status': sur_status_list,
                'sur_description': sur_description_list,
                'rwy_twy_title': rwy_twy_title_list,
                'rwy_twy_status': rwy_twy_status_list,
                'rwy_twy_description': rwy_twy_description_list,
                'lgt_title': lgt_title_list,
                'lgt_status': lgt_status_list,
                'lgt_description': lgt_description_list,
                'eqp_title': eqp_title_list,
                'eqp_status': eqp_status_list,
                'eqp_description': eqp_description_list,
                'event_com': event_com,
                'event_nav': event_nav,
                'event_sur': event_sur,
                'event_rwy_twy': event_rwy_twy,
                'event_lgt': event_lgt,
                'event_eqp': event_eqp,
                'event_rwy_in_use': event_rwy_in_use,
                'event_rwy_inspection': event_rwy_inspection,
                'event_rpv': event_rpv,
                'event_other': event_other
                }
                }
                )
            session['filled_log_data_flag'] = 1
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('logs', log_no=int(log_no)))

    else:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    return render_template('index.html',
        navigator="logs edit",
        log_no=int(log_no),
        result=result,
        log_records_list=session['log_records_list'],
        first_list=first_list,
        last_list=last_list,
        team_members=session['all_members'],
        counter=largest_len+1
        )

@app.route('/other forms/<form_number>', methods=['GET', 'POST'])
def other_forms(form_number):
    if form_number == 'E101':
        nav = "e101"
    elif form_number == 'E102':
        nav = "e102"
    elif form_number == 'E103':
        nav = "e103"
    elif form_number == 'E104':
        nav = "e104"
    elif form_number == 'E105':
        nav = "e105"
    elif form_number == 'E106':
        nav = "e106"
    elif form_number == 'E107':
        nav = "e107"
    elif form_number == 'E108':
        nav = "e108"


    return render_template('index.html',
        navigator="other forms",
        nav=nav,
        log_records_list=session['log_records_list']
        )

@app.route('/fids/<airport>/<arr_dep>', methods=['GET', 'POST'])
def fids(airport, arr_dep):
    l = []
    en_name = []
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
    session['current_id'] = cursor.log_records.estimated_document_count()

    if airport == 'OICC':
        html = "https://fids.airport.ir/111/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%DA%A9%D8%B1%D9%85%D8%A7%D9%86%D8%B4%D8%A7%D9%87"
    elif airport == 'OIII':
        html = "https://fids.airport.ir/2/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%D9%85%D9%87%D8%B1%D8%A2%D8%A8%D8%A7%D8%AF"
    elif airport == 'OIMM':
        html = "https://fids.airport.ir/102/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%D9%85%D8%B4%D9%87%D8%AF"
    elif airport == 'OISS':
        html = "https://fids.airport.ir/1/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%D8%B4%D9%8A%D8%B1%D8%A7%D8%B2"
    #elif airport == 'OIBK':
        #html = ""
    elif airport == 'OIKB':
        html = "https://fids.airport.ir/117/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%D8%A8%D9%86%D8%AF%D8%B1%D8%B9%D8%A8%D8%A7%D8%B3"
    #elif airport == 'OIBP':
        #html = ""
    elif airport == 'OIAW':
        html = "https://fids.airport.ir/401/%D8%A7%D8%B7%D9%84%D8%A7%D8%B9%D8%A7%D8%AA-%D9%BE%D8%B1%D9%88%D8%A7%D8%B2-%D9%81%D8%B1%D9%88%D8%AF%DA%AF%D8%A7%D9%87-%D8%A7%D9%87%D9%88%D8%A7%D8%B2"
    #elif airport == 'OIKQ':
        #html = ""
    else:
        html = ""

    if html:
        try:
            r = requests.get(html).text
            soup = BeautifulSoup(r, "html.parser")

            for tr in soup.find_all('tr'):
                tds = tr.find_all('td')
                if len(tds):
                    l_tds = []
                    for i in range(len(tds)):
                        l_tds.append(tds[i].text)
                    l.append(l_tds)
                    en_name.append(utils.fa_airports_name_to_en_name(l_tds[3]))
            if request.args.get('call_sign'):
                for item in l:
                    if request.args.get('call_sign') in item:
                        l = []
                        en_name = []
                        l.append(item)
                        en_name.append(utils.fa_airports_name_to_en_name(item[3]))
                        break
        except requests.exceptions.RequestException as e:
            print(e)

    return render_template('index.html',
        navigator="fids",
        airport=airport,
        arr_dep=arr_dep,
        log_records_list=session['log_records_list'],
        s=l,
        en_name=en_name
        )

@app.route('/present members/<log_no>')
def present_members(log_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    else:
        photo_path = []
        signature_path = []
        present_members = []
        result = cursor.log_records.find_one({"id": int(log_no)})
        for name in result['team_members']:
            users_result = cursor.users.find_one({"initial": name[1]})
            if users_result:
                if users_result['photo']:
                    file_like = io.BytesIO(users_result['photo'])
                    photo = PIL.Image.open(file_like)
                    if users_result['photo_file_type'] == 'jpg':
                        photo.save(os.path.join(app.config['SAVE_FOLDER'], users_result['username']+'_photo.'+users_result['photo_file_type']), "JPEG")
                        photo_path.append([name[1], url_for('static', filename='img/' + users_result['username'] +'_photo.'+users_result['photo_file_type'])])
                    else:
                        photo.save(os.path.join(app.config['SAVE_FOLDER'], users_result['username']+'_photo.'+users_result['photo_file_type']), users_result['photo_file_type'].upper())
                        photo_path.append([name[1], url_for('static', filename='img/' + users_result['username'] +'_photo.'+users_result['photo_file_type'])])
                else:
                    photo_path.append([name[1],
                        url_for('static', filename='img/person.png')])
                if users_result['signature']:
                    file_like2 = io.BytesIO(users_result['signature'])
                    signature = PIL.Image.open(file_like2)
                    if users_result['signature_file_type'] == 'jpg':
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], users_result['username']+'_signature.'+users_result['signature_file_type']), "JPEG")
                        signature_path.append([name[1], url_for('static', filename='img/' + users_result['username'] +'_signature.'+users_result['signature_file_type'])])
                    else:
                        signature.save(os.path.join(app.config['SAVE_FOLDER'], users_result['username']+'_signature.'+users_result['signature_file_type']), users_result['signature_file_type'].upper())
                        signature_path.append([name[1], url_for('static', filename='img/' + users_result['username'] +'_signature.'+users_result['signature_file_type'])])
                else:
                    signature_path.append([name[1], url_for('static', filename='img/no_signature.jpg')])
            else:
                photo_path.append([name[1], url_for('static', filename='img/person.png')])
                signature_path.append([name[1], url_for('static', filename='img/no_signature.jpg')])

    return render_template('includes/_presentMembers.html',
    present_members=present_members,
    log_no=log_no,
    result=result,
    photo_path=photo_path,
    signature_path=signature_path
    )

@app.route('/adsb/<airport>')
def adsb(airport):
    #adsb_cursor = utils.config_mongodb("172.27.13.68", 27017, 'ADSB-BL')
    rule = request.url_rule
    if session['adsb_db']:
        print("********")
        location = session['adsb_db']
        print(location)
        print("********")
    else:        
        location = [
        {
            'icon': 'http://maps.google.com/mapfiles/ms/icons/green-dot.png',
            'lat': 35.6900,
            'lng': 51.3112,
            'infobox': "<b>Mehrabad Airport</b>"
        }
        ]
    
    airport = Map(
        identifier="airport",
        lat = 35.6900,
        lng = 51.3112,
        style = "height:79vh;width:62vw;margin:-8px 0 0 0;",
        zoom = 8,
        maptype = "TERRAIN",
        fullscreen_control=False,
        markers = [{'icon': location[i]['icon'], 'lat':location[i]['lat'] ,
        'lng':location[i]['lng'] , 'infobox':location[i]['infobox']} for i in range(len(location))]
    )

    return render_template('index.html',
        navigator="map",
        log_records_list=session['log_records_list'],
        airport=airport
    )

@app.route('/adsb/<airport>/get data')
def adsb_get_data(airport):
    adsb_cursor = utils.config_mongodb("172.27.13.68", 27017, 'ADSB-BL')
    rule = request.url_rule
    location = [
    {
        'icon': 'http://maps.google.com/mapfiles/ms/icons/green-dot.png',
        'lat': 35.6900,
        'lng': 51.3112,
        'infobox': "<b>Mehrabad Airport</b>"
    }
    ]
    full_result = adsb_cursor.active_flights.find().limit(0).sort("_id", -1)
    if full_result:
        for r in full_result:
            location.append(
                {
                    'icon': '/static/img/aircraft icon/A320.png',
                    'lat': r['latitude'],
                    'lng': r['longitude'],
                    'infobox': "<b>"+r['call_sign']+"</b>"
                }
                )
        session['adsb_db'] = location
        print(session['adsb_db'])
        flash("Successful!", "success")
    else:
        flash("your data can not be fetched", "error")
    
    airport = Map(
        identifier="airport",
        lat = 35.6900,
        lng = 51.3112,
        style = "height:79vh;width:62vw;margin:-8px 0 0 0;",
        zoom = 8,
        maptype = "TERRAIN",
        fullscreen_control=False
    )

    return render_template('index.html',
        navigator="map",
        log_records_list=session['log_records_list'],
        airport=airport
    )

@app.route('/New Message/<msg_type>/<log_no>', methods=['GET', 'POST'])
def new_message(msg_type, log_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    else:
        new_msg = {}
        if request.method == 'POST':
            new_msg['datetime'] = datetime.datetime.utcnow()
            new_msg['full_message'] = request.form.get('new-message')
            new_msg['id'] = int(log_no)

            if msg_type == 'Notam':
                processed_notam = utils.notam_processing(new_msg['full_message'])
                new_msg['tsa'] = processed_notam[0]
                new_msg['notam_no'] = processed_notam[1]
                new_msg['aero'] = processed_notam[2]
                new_msg['E'] = processed_notam[3]

                amhs_cursor.notam.insert_one(new_msg)
                result_records = amhs_cursor.records.find_one({"id": int(log_no)})
                if result_records['notam']:
                    notam_item = result_records['notam']
                else:
                    notam_item = []
                notam_item.append(new_msg['notam_no'])
                amhs_cursor.records.update_many(
                            {"id": new_msg['id']},
                            {'$set': {
                            'notam': notam_item
                            }
                            }
                            )
            elif msg_type == 'Permission':
                processed_perm = utils.permission_processing(new_msg['full_message'])
                new_msg['tsa'] = processed_perm[0]
                new_msg['perm_ref'] = processed_perm[1]
                new_msg['from'] = processed_perm[2]
                new_msg['operatore'] = processed_perm[3]
                new_msg['ir fpn'] = processed_perm[4]
                new_msg['granted'] = processed_perm[5]
                new_msg['origin_ref'] = processed_perm[6]
                new_msg['granted_ref'] = processed_perm[7]
                if new_msg['granted_ref']:
                    perm_res = amhs_cursor.permission.find_one({"origin_ref": new_msg['granted_ref']})
                    if perm_res:
                        new_msg['perm_ref'] = perm_res['perm_ref']
                        new_msg['from'] = perm_res['from']
                        new_msg['operatore'] = perm_res['operatore']
                        new_msg['origin_ref'] = perm_res['origin_ref']
                    else:
                        new_msg['perm_ref'] = "ref not found"
                amhs_cursor.permission.insert_one(new_msg)
                result_records = amhs_cursor.records.find_one({"id": int(log_no)})
                if result_records['perm']:
                    perm_item = result_records['perm']
                else:
                    perm_item = []
                perm_item.append((new_msg['tsa'], new_msg['perm_ref']))
                amhs_cursor.records.update_many(
                            {"id": new_msg['id']},
                            {'$set': {
                            'perm': perm_item
                            }
                            }
                            )

    return render_template('includes/_newNotamPermMessage.html')

@app.route('/Notam/<notam_no>')
def notam(notam_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    else:
        notam_no = notam_no.replace('-', '/')
        result_notam = amhs_cursor.notam.find_one({"notam_no": notam_no})
        notam_msg = result_notam['full_message']
    return render_template('includes/_notampermMessage.html', msg=notam_msg)

@app.route('/Permission/<id_num>/<tsa>/<ref>/<granted>')
def permission(id_num, tsa, ref, granted):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    else:
        print(id_num, ref, granted)
        if "not found" not in ref:
            print(ref)
            ref = ref.replace('-', '/')
            result_permission = amhs_cursor.permission.find_one({"perm_ref": ref, "granted":granted})
        else:
            print(ref)
            result_permission = amhs_cursor.permission.find_one({"id": int(id_num), "tsa": tsa, "granted":granted})
        perm_msg = result_permission['full_message']
    return render_template('includes/_notampermMessage.html', msg=perm_msg)

@app.route('/Delete/<id_num>/<tsa>/<indicator>')
def delete(id_num, tsa, indicator):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    else:
        indicator = indicator.replace('-', '/')
        if indicator[0] in ('A', 'B'):
            selected_notam = amhs_cursor.notam.find_one({"notam_no": indicator})
            if selected_notam:
                related_log = amhs_cursor.records.find_one({"id": selected_notam['id']})
                amhs_cursor.notam.delete_one({"notam_no": indicator})
                index = related_log['notam'].index(indicator)
                related_log['notam'].pop(index)
                amhs_cursor.records.update_many({"id": related_log['id']}, {'$set': {'notam': related_log['notam']}})
                return redirect(request.referrer)
        else:
            selected_perm = amhs_cursor.permission.find_one({"id": int(id_num), "tsa": tsa, "perm_ref": indicator})
            if selected_perm:
                related_log = amhs_cursor.records.find_one({"id": selected_perm['id']})
                amhs_cursor.permission.delete_one({"id": int(id_num), "tsa": tsa, "perm_ref": indicator})
                index = related_log['perm'].index([tsa, indicator])
                related_log['perm'].pop(index)
                amhs_cursor.records.update_many({"id": related_log['id']}, {'$set': {'perm': related_log['perm']}})
                return redirect(request.referrer)

@app.errorhandler(500)
def internal_error(exception):
    app.logger.exception(exception)
    file_handler = RotatingFileHandler('C:/inetpub/wwwroot/logs.log', 'a', 1 * 1024 * 1024, 10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('microblog startup')
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug = True)
