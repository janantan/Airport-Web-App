from flask import Flask, render_template, flash, redirect, url_for, session, request, jsonify
from flask import Response, logging, Markup, abort, after_this_request, make_response
from flask_googlemaps import GoogleMaps, Map, icons
from functools import wraps
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from PIL import Image
from bs4 import BeautifulSoup
import io
from io import StringIO
import urllib3
import PIL.Image
import requests
import re
import jwt
import codecs
import os
import json
import datetime
import jdatetime
import uuid
import pdfkit
import pathlib
import utils, config, equipments

cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.DB_NAME)
amhs_cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.AMHS_DB_NAME)
users_cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.USERS_DB_NAME)
UPLOAD_FOLDER = 'E:/BL/amhs_log/static/uploded_files/save_folder'
ATTACHED_FILE_FOLDER = 'E:/BL/amhs_log/static/attached_files'
SAVE_FOLDER = 'E:/BL/amhs_log/static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
 
app.secret_key = 'secret@airport_web_app@password_hash@840'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ATTACHED_FILE_FOLDER'] = ATTACHED_FILE_FOLDER
app.config['SAVE_FOLDER'] = SAVE_FOLDER
#set key as config for googlemaps
#app.config['GOOGLEMAPS_KEY'] = "AIzaSyBlWehb6tP8Fn5VqGEgcoounuDwx8k-mY8"
app.config['GOOGLEMAPS_KEY'] = "AIzaSyBU6HCTk7D2VgNHL-FJ6KSpDO0BQxPbuxw"
# Initialize the extension
GoogleMaps(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'loged_in' not in session:
            flash('Please Sign in First!', 'danger')
            return redirect(url_for('logout'))

        if 'access-token' in request.headers['Cookie']:
            Token = request.headers['Cookie'].split(' ')
            token = Token[0][13:-1]

        if not token:
            flash('Token is missing!', 'danger')
            return redirect(request.referrer)

        try:
            data = jwt.decode(token, app.secret_key)
        except:
            flash('Token is Invalid or Expired! Please Sign in Again.', 'danger')
            return redirect(url_for('logout'))            

        result = users_cursor.users.find_one({"user_id": data['user_id']})
        if result:
            if 'username' not in session:
                username = result['username']
                session['username'] = username
                flash('Welcome '+result['first_name']+" "+result['last_name']+'!', 'success-login')
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
                session['airport'] = result['airport']
                session['admin'] = result['admin']
                session['AMHS form'] = result['AMHS form']
                session['IT form'] = result['IT form']
                session['message'] = result['first_name']+" "+result['last_name']
        
        else:
            flash('Token is invalid!', 'danger')
            return redirect(request.referrer)

        return f(*args, **kwargs)
    return decorated

@app.route('/badrequest400')
def bad_request():
    return abort(403)

@app.errorhandler(401)
def custom_401(error):
    return Response('Could not Verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

@app.route('/home', methods=['GET', 'POST'])
@token_required
def home():
    session['log_no'] = cursor.log_records.estimated_document_count()
    session['amhs_log_no'] = amhs_cursor.records.estimated_document_count()
    session['it_log_no'] = amhs_cursor.it_records.estimated_document_count()
    if users_cursor.users.find_one({'username': session['username']})['initial']:
        session['initial'] = users_cursor.users.find_one({'username': session['username']})['initial']
    else:
        session['initial'] = None
    session['adsb_db'] = []
    session['metar'] = utils.metar(session['airport'])

    if session['amhs_log_no'] and (session['department'] == 'Aeronautical Information and Communication Technology'):
        amhs_result = amhs_cursor.records.find_one({"id": session['amhs_log_no']})
        if utils.if_today_shift(amhs_result):
            session['log_records_list'] = utils.shift_brief(amhs_result, session['department'])
            if amhs_cursor.it_records.find_one({"shift_date": amhs_result['shift_date']}):
                session['log_records_list'].insert(6, amhs_cursor.it_records.find_one({"shift_date": amhs_result['shift_date']})['present_members'])

    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['log_data_flag'] = 0

    if not session.get('log_records_list', default=None):
        session['log_records_list'] = []

    #return redirect(url_for('fids', airport=session['airport'], arr_dep="all"))
    if session['admin']:
        unchecked_amhs_log = amhs_cursor.records.find_one({"checked": False})
        unchecked_it_log = amhs_cursor.it_records.find_one({"checked": False})
        if unchecked_it_log:
            session['unchecked_it_log'] = unchecked_it_log['id']
        else:
            session['unchecked_it_log'] = session['it_log_no']
        if unchecked_amhs_log:
            return redirect(url_for('amhs_log', id_no=unchecked_amhs_log['id']))

    if (session['AMHS form'] and session['amhs_log_no']):
        return redirect(url_for('amhs_log', id_no=session['amhs_log_no']))
    elif (session['IT form'] and session['it_log_no']):
        return redirect(url_for('it_logs', id_no=session['it_log_no'], form_number="None"))
    else:
        return render_template('index.html',
            navigator="None",
            log_records_list=session['log_records_list'],
            title=''
            )

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    @after_this_request
    def add_header(response):
        response.headers['Set-Cookie'] = '%s=%s'%('access-token',token)
        response.headers.add('X-Access-Token', token)
        return response
    
    token = None
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        result = users_cursor.users.find_one({"username": username})

        if result:
            if sha256_crypt.verify(password, result['password']):
                session['loged_in'] = True
                TOKEN = jwt.encode({'user_id':result['user_id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                    app.secret_key)
                token = TOKEN.decode('UTF-8')
                return redirect(url_for('home'))
            else:
                flash('The Password Does Not Match!', 'danger')
        else:
            flash('Not Signed up Username! Please Sign up First.', 'error')
    return render_template('home.html', title='')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = {'created_date': datetime.datetime.now()}
        users['first_name'] = request.form.get('first_name')
        users['last_name'] = request.form.get('last_name')
        users['airport'] = request.form.get('airport')
        users['department'] = request.form.get('department')
        users['initial'] = request.form.get('initial').upper()
        users['email'] = request.form.get('email')
        users['phone'] = request.form.get('phone')
        users['username'] = request.form.get('username')
        users['admin'] = False
        if request.form.get('department') == 'Aeronautical Information and Communication Technology':
            if request.form.get('initial'):
                users['AMHS form'] = True
            else:
                users['AMHS form'] = False
            users['IT form'] = True
        new_password = request.form.get('password')
        confirm = request.form.get('confirm')

        result = users_cursor.users.find_one({"username": users['username']})

        if result:
            flash('Repeated Username! Please Try Another Username.', 'danger')
            return redirect(url_for('register'))
        else:
            if new_password == confirm:                    
                users['password'] = sha256_crypt.hash(str(request.form.get('password')))
                users['user_id'] = str(uuid.uuid4())
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

                users_cursor.users.insert_one(users)
                message = Markup("Successful Sine up! Please <a style='color:#3c763d; font-weight: bold;' href='/login'>Sign in</a>.")
                flash(message, 'success')
                return redirect(url_for('login'))
            else:
                flash('The Password Does Not Match!', 'error')
                return redirect(url_for('register'))
            
    return render_template('register.html', title='register')

@app.route('/change password', methods=['GET', 'POST'])
@token_required
def change_password():
    if request.method == 'POST':
        current_pass = request.form.get('current_pass')
        new_pass = request.form.get('password')
        confirm = request.form.get('confirm')
        
        result = users_cursor.users.find_one({"username": session['username']})

        if sha256_crypt.verify(current_pass, result['password']):
            if new_pass == confirm:
                new_pass = sha256_crypt.hash(str(new_pass))
                users_cursor.users.update_many(
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
        title='change password',
        log_records_list=session['log_records_list']
        )

@app.route('/amhs-pdf/<log_no>')
def amhs_pdf(log_no):

    result = amhs_cursor.records.find_one({"id": int(log_no)})

    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)

    msg_flag = 0
    for msg in equipments.amhs_msg_list:
        if result[msg]:
            msg_flag = 1
            break
    (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
    
    signature_path = []
    for sign in result['signature_path']:
        signature_path.append('E:/BL/amhs_log/'+sign)

    pdfkit.from_string(render_template('includes/_forAmhsPdf.html',
        result=result,
        log_records_list=session['log_records_list'],
        log_no=int(log_no),
        channel_list=equipments.amhs_channel_list,
        msg_list=equipments.amhs_msg_list,
        server_room_eqp=equipments.amhs_server_room_eqp,
        network=equipments.amhs_network,
        msg_flag=msg_flag,
        notam_data=notam_data,
        perm_data=perm_data,
        title='amhs log pdf',
        signature_path=signature_path
        ), 'static/pdf/amhs/log number '+log_no+'.pdf')
    os.startfile('E:/BL/amhs_log/static/pdf/amhs/log number '+log_no+'.pdf')

    return redirect(url_for('amhs_log', id_no=int(log_no)))

@app.route('/logout')
def logout():
    session.pop('datetime', None)
    session.pop('jdatetime', None)
    session.pop('current_id', None)
    session.pop('log_records_list', None)
    session.pop('username', None)
    session.pop('loged_in', None)
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
    session.pop('admin', None)
    session.pop('AMHS form', None)
    session.pop('IT form', None)
    session.pop('administration', None)
    session.pop('amhs_log_no', None)
    session.pop('it_log_no', None)

    return redirect(url_for('login'))

@app.route('/<navigator>', methods=['GET', 'POST'])
@token_required
def index(navigator):
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    flt_form_list = []
    flt_scheldule_dict = {}
    wd = []
    result_count_list = []

    return render_template('index.html',
        datetime=session['datetime'],
        navigator=navigator,
        title=navigator,
        log_no=session['log_no'],
        flt_scheldule_dict=flt_scheldule_dict,
        week_days=wd,
        result_count_list=result_count_list,
        flt_form_list=flt_form_list,
        result_count=0,
        flash=redirect(url_for('bad_request')),
        log_records_list=session['log_records_list']
        )

@app.route('/search', methods=['GET', 'POST'])
@token_required
def search():
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    i = 1
    l = []
    result_list = []
    search_field = ""

    users_result = users_cursor.users.find({'department': 'Aeronautical Information and Communication Technology', 'airport':session['airport']})
    AICT_personel = []
    AICT_initial = []
    for r in users_result:
        AICT_personel.append(r['first_name']+' '+r['last_name'])
        if r['initial']:
            AICT_initial.append(r['initial'])

    if request.method == 'POST':

        search_field = request.form.get('search_field')

        if request.form.get('from'):
            d_from = request.form.get('from')
            date_from = datetime.datetime.strptime(d_from, "%Y-%m-%d")
            date_from = date_from.strftime('%Y - %m - %d')
        elif request.form.get('i_from'):
            d_from = request.form.get('i_from')
            date_from = datetime.datetime.strptime(d_from, "%Y-%m-%d")
            date_from = date_from.strftime('%Y - %m - %d')
        else:
            date_from = ""

        if request.form.get('to'):
            d_to = request.form.get('to')
            date_to = datetime.datetime.strptime(d_to, "%Y-%m-%d")
            date_to = date_to.strftime('%Y - %m - %d')
        elif request.form.get('i_to'):
            d_to = request.form.get('i_to')
            date_to = datetime.datetime.strptime(d_to, "%Y-%m-%d")
            date_to = date_to.strftime('%Y - %m - %d')
        else:
            date_to = ""

        if request.form.get('initial'):
            initial = request.form.get('initial').upper()
        else:
            initial = ""

        if request.form.get('name'):
            name = request.form.get('name')
        else:
            name = ""

        if request.form.get('remark'):
            remark = request.form.get('remark').upper()
        elif request.form.get('i_remark'):
            remark = request.form.get('i_remark').upper()
        else:
            remark = ''

        if request.form.get('shift'):
            shift = request.form.get('shift')
        else:
            shift = ''

        if request.form.get('search_field') == "AMHS Logs":
            if initial and shift and remark:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    '$and':[
                    {'shift': shift},
                    {'remarks': {'$regex': remark }},
                    {'$or':[{'on_duty': {'$elemMatch':{'$eq':initial}}}, {'overtime': {'$elemMatch':{'$eq':initial}}}]}
                    ]
                    })
            elif initial and shift:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    '$and':[
                    {'shift': shift},
                    {'$or':[{'on_duty': {'$elemMatch':{'$eq':initial}}}, {'overtime': {'$elemMatch':{'$eq':initial}}}]}
                    ]
                    })
            elif initial and remark:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    '$and':[
                    {'remarks': {'$regex': remark }},
                    {'$or':[{'on_duty': {'$elemMatch':{'$eq':initial}}}, {'overtime': {'$elemMatch':{'$eq':initial}}}]}
                    ]
                    })
            elif shift and remark:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    '$and':[
                    {'remarks': {'$regex': remark }},
                    {'shift': shift}
                    ]
                    })
            elif initial:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    '$or':[{'on_duty': {'$elemMatch':{'$eq':initial}}}, {'overtime': {'$elemMatch':{'$eq':initial}}}]
                    })
            elif shift:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    'shift': shift
                    })
            elif remark:
                result = amhs_cursor.records.find({
                    'shift_date': {'$gte': date_from, '$lt': date_to},
                    'remarks': {'$regex': remark }
                    })
            else:
                print('else')
                result = amhs_cursor.records.find({'shift_date': {'$gte': date_from, '$lt': date_to}})

        
        elif request.form.get('search_field') == "IT Logs":
            if name and remark:
                result = amhs_cursor.it_records.find({
                        'shift_date': {'$gte': date_from, '$lt': date_to},
                        '$and':[
                        {'remarks': {'$regex': remark}},
                        {'$or':[{'present_members': {'$elemMatch':{'$eq':name}}}]}
                        ]
                        })
            elif name:
                result = amhs_cursor.it_records.find({
                        'shift_date': {'$gte': date_from, '$lt': date_to},
                        '$or':[{'present_members': {'$elemMatch':{'$eq':name}}}]
                        })
            elif remark:
                result = amhs_cursor.it_records.find({
                        'shift_date': {'$gte': date_from, '$lt': date_to},
                        'remarks': {'$regex': remark}
                        })
            else:
                result = amhs_cursor.it_records.find({'shift_date': {'$gte': date_from, '$lt': date_to}})

        if result:
            if search_field == 'AMHS Logs':
                for r in result:
                    l = [i, (', '.join(r['on_duty'])), r['shift'], r['shift_date'], r['id'], utils.checked(r['checked'])]
                    result_list.append(l)
                    i = i+1
            elif search_field=='IT Logs':
                for r in result:
                    l = [i, (', '.join(r['present_members'])), r['shift_date'], r['id'], utils.checked(r['checked'])]
                    result_list.append(l)
                    i = i+1
        else:
            flash('There is no record!', 'error')

        if not result_list:
            flash('There is no record!', 'error')

    return render_template('index.html',
        navigator="search",
        title='search',
        log_records_list=session['log_records_list'],
        result_list=result_list,
        search_field=search_field,
        AICT_personel=AICT_personel,
        AICT_initial=AICT_initial
        )

@app.route('/user-roles', methods=['GET', 'POST'])
@token_required
def user_roles():
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    if not session['admin']:
        flash('You Have not Permission to Assign Roles!', 'error')
        return redirect(request.referrer)
    users = users_cursor.users.find({'department':'Aeronautical Information and Communication Technology', 'airport':session['airport']})
    result_list = []
    for user in users:
        result_list.append([user['first_name'], user['last_name'], user['username'], user['initial'], user['admin'], user['AMHS form'], user['IT form']])
    
    if request.method == 'POST':
        for user in result_list:
            users_cursor.users.update_many(
                {"username": user[2]},
                {'$set': {
                'username': user[2],
                'admin':True if 'admin' in request.form.getlist(user[2]+'_user_roles') else False,
                'AMHS form':True if 'amhs' in request.form.getlist(user[2]+'_user_roles') else False,
                'IT form':True if 'it' in request.form.getlist(user[2]+'_user_roles') else False
                }
                }
                )
            if user[2] == session['username']:
                curent_user = users_cursor.users.find_one({'username': user[2]})
                session['admin'] = curent_user['admin']
                session['AMHS form'] = curent_user['AMHS form']
                session['IT form'] = curent_user['IT form']
        flash('Saved Successfuly!', 'success')
        return redirect(url_for('user_roles'))

    return render_template('index.html',
        navigator="user-roles",
        title='user roles',
        log_records_list=session['log_records_list'],
        result=result_list
        )

@app.route('/amhs log form', methods=['GET', 'POST'])
@token_required
def amhs_log_form():

    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    if not session['AMHS form']:
        flash('You Have not Permission to Fill out the Log!', 'error')
        return redirect(request.referrer)

    result = amhs_cursor.records.find_one({"id": amhs_cursor.records.estimated_document_count()})
    wd = datetime.datetime.utcnow().weekday()
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
    today = session['datetime']
    attachments_path_list = []
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

    if result:
        if (today==result['shift_date'] and today_shift==result['shift']):
            logdata = result
            session['log_records_list'] = utils.shift_brief(result, session['department'])
            if amhs_cursor.it_records.find_one({"shift_date": today}):
                session['log_records_list'].insert(6, amhs_cursor.it_records.find_one({"shift_date": today})['present_members'])
            (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
            if 'attachments' in logdata:
                for i in range(len(logdata['attachments']['attached_file_type'])):
                    file_path = url_for('static',
                        filename='attached_files/amhs log no ' + str(amhs_cursor.records.estimated_document_count()) +'/'+logdata['attachments']['title'][i]+'.'+logdata['attachments']['attached_file_type'][i])
                    attachments_path_list.append(file_path)
        else:
            logdata = {}
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
            record['shift_switch'] = [""]
            record['overtime'] = [""]
            record['daily_leave'] = [""]
            record['day'] = today_wd
            record['shift'] = today_shift
            record['team'] = ''
            server_room_equipment = {}
            for eqp in equipments.amhs_server_room_eqp:
                server_room_equipment[eqp] = {'status':'On', 'remark':''}
            record['server_room_equipment'] = server_room_equipment
            record['room_temp'] = ''
            channels_status = {}
            for channel in equipments.amhs_channel_list: 
                channels_status[channel] = {
                'during':'OK',
                'from':'',
                'to':'',
                'reason':'',
                'end':'OK'
                }
            record['channels_status'] = channels_status
            record['fpl'] = record['dla'] = record['chg'] = ""
            record['notam'] = record['perm'] = []
            record['attachments'] = {'title':[], 'attached_file_type':[]}
            record['signature_path']=[]
            record['signature_path'].append(session['signature_path'])
            record['checked'] = False
            amhs_cursor.records.insert_one(record)
            session['amhs_log_no'] = amhs_cursor.records.estimated_document_count()
    else:
        logdata = {}
        notam_data = None
        perm_data = None
        record = {'event_date': datetime.datetime.utcnow()}
        record['id'] = 1
        record['shift_date'] = session['datetime']
        record['shift_jdate'] = session['jdatetime']
        record['on_duty'] = utils.regex(session['initial'])
        record['shift_switch'] = [""]
        record['overtime'] = [""]
        record['daily_leave'] = [""]
        record['day'] = today_wd
        record['shift'] = today_shift
        record['team'] = ''
        server_room_equipment = {}
        for eqp in equipments.amhs_server_room_eqp:
            server_room_equipment[eqp] = {'status':'On', 'remark':''}
        record['server_room_equipment'] = server_room_equipment
        record['room_temp'] = ''
        channels_status = {}
        for channel in equipments.amhs_channel_list: 
            channels_status[channel] = {
            'during':'OK',
            'from':'',
            'to':'',
            'reason':'',
            'end':'OK'
            }
        record['channels_status'] = channels_status
        record['fpl'] = record['dla'] = record['chg'] = ""
        record['notam'] = record['perm'] = []
        record['attachments'] = {'title':[], 'attached_file_type':[]}
        record['signature_path']=[]
        record['signature_path'].append(session['signature_path'])
        record['checked'] = False
        amhs_cursor.records.insert_one(record)
        session['amhs_log_no'] = amhs_cursor.records.estimated_document_count()

    if request.method == 'POST':
        server_room_equipment = {}
        for eqp in equipments.amhs_server_room_eqp: 
            server_room_equipment[eqp] = {'status':request.form.get(eqp), 'remark':request.form.get(eqp+' remark')}
        channels_status = {}
        for channel in equipments.amhs_channel_list: 
            channels_status[channel] = {
            'during':request.form.get(channel+'_during'),
            'from':request.form.get(channel+'_from'),
            'to':request.form.get(channel+'_to'),
            'reason':request.form.get(channel+'_reason'),
            'end':request.form.get(channel+'_end')
            }
        attachments = {'title':[], 'attached_file_type':[]}
        if logdata:
            attachments = logdata['attachments']
        for i in range (1, 100):
            if 'attachments_'+str(i) in request.files:
                attachments['title'].append(request.form.get('title_'+str(i)))
                file = request.files['attachments_'+str(i)]
                filename1 = secure_filename(file.filename)
                    #if allowed_file(filename1):
                file.save(os.path.join(app.config['ATTACHED_FILE_FOLDER'], filename1))
                file_type  = filename1.rsplit('.', 1)[1].lower()
                #opened_file = open(app.config['ATTACHED_FILE_FOLDER']+'/'+filename1, 'rb').read()
                directory = app.config['ATTACHED_FILE_FOLDER']+'/'+'amhs log no '+str(session['amhs_log_no'])
                if not os.path.exists(directory):
                    os.makedirs(directory)
                os.rename(app.config['ATTACHED_FILE_FOLDER']+'/'+filename1,
                    directory+'/'+request.form.get('title_'+str(i))+'.'+ file_type)
                attachments['attached_file_type'].append(file_type)
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
            'room_temp': request.form.get('room_temp'),
            'server_room_equipment': server_room_equipment,
            'channels_status': channels_status,
            'fpl': request.form.get('fpl'),
            'dla': request.form.get('dla'),
            'chg': request.form.get('chg'),
            'remarks': request.form.get('remarks').split("\n"),
            'attachments': attachments
            }
            }
            )
        update_signature = amhs_cursor.records.find_one({"id": session['amhs_log_no']})
        update_signature_path=[]
        if update_signature:
            od = update_signature['on_duty'] if update_signature['on_duty'][0] else []
            ov = update_signature['overtime'] if update_signature['overtime'][0] else []
            for initial in od+ov:
                signature_result = users_cursor.users.find_one({'initial': initial})
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
        title= 'amhs log form',
        log_no=session['amhs_log_no'],
        wd=today_wd,
        result = logdata,
        today_shift=today_shift,
        channel_list=equipments.amhs_channel_list,
        server_room_eqp=equipments.amhs_server_room_eqp,
        msg_list=equipments.amhs_msg_list,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data,
        attachments=attachments_path_list
        )

@app.route('/amhs logs/<id_no>', methods=['GET', 'POST'])
@token_required
def amhs_log(id_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    result = amhs_cursor.records.find_one({"id": int(id_no)})
    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)
    
    users_result = users_cursor.users.find_one({'username': session['username']})
    if users_result:
        if users_result['initial']:
            initial = users_result['initial']
        else:
            initial = None
    else:
        initial = None
    msg_flag = 0
    for msg in equipments.amhs_msg_list:
        if result[msg]:
            msg_flag = 1
            break
    (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
    attachments = []
    if 'attachments' in result:
        for i in range(len(result['attachments']['attached_file_type'])):
            file_path = url_for('static',
                filename='attached_files/amhs log no ' + id_no +'/'+result['attachments']['title'][i]+'.'+result['attachments']['attached_file_type'][i])
            print(file_path)
            attachments.append(file_path)

    return render_template('index.html',
        navigator="amhs logs",
        title='amhs log number '+id_no,
        log_no=int(id_no),
        result = result,
        initial=initial,
        channel_list=equipments.amhs_channel_list,
        msg_list=equipments.amhs_msg_list,
        server_room_eqp=equipments.amhs_server_room_eqp,
        msg_flag=msg_flag,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data,
        attachments=attachments
        )

@app.route('/amhs-ck/<id_no>')
@token_required
def amhs_ck(id_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    result = amhs_cursor.records.find_one({"id": int(id_no)})
    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)        
    if not session['admin']:
        flash('You Have not Permission to Check the Log!', 'error')
        return redirect(request.referrer)
    amhs_cursor.records.update_many(
            {"id": int(id_no)},
            {'$set': {
            'id': int(id_no),
            'checked': True
            }})
    flash('Checked', 'success')
    if int(id_no) < session['amhs_log_no']:
        unchecked_log = amhs_cursor.records.find_one({"checked": False})
        if unchecked_log:
            return redirect(url_for('amhs_log', id_no=unchecked_log['id']))
        else:
            return redirect(url_for('amhs_log', id_no=session['amhs_log_no']))
    else:
        return redirect(url_for('amhs_log', id_no=session['amhs_log_no']))


@app.route('/amhs logs/<id_no>/edit', methods=['GET', 'POST'])
@token_required
def edit_amhs_log(id_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    result = amhs_cursor.records.find_one({"id": int(id_no)})
    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)
        
    if (not session['AMHS form']) or (session['initial'] not in result['on_duty']+result['overtime']):
        flash('You Have not Permission to Edit the Log!', 'error')
        return redirect(request.referrer)

    (notam_data, perm_data) = utils.notam_permission_data(result, amhs_cursor)
    attachments_path_list = []
    if 'attachments' in result:
        for i in range(len(result['attachments']['attached_file_type'])):
            file_path = url_for('static',
                filename='attached_files/amhs log no ' + str(amhs_cursor.records.estimated_document_count()) +'/'+result['attachments']['title'][i]+'.'+result['attachments']['attached_file_type'][i])
            attachments_path_list.append(file_path)
    if request.method == 'POST':
        server_room_equipment = {}
        for eqp in equipments.amhs_server_room_eqp: 
            server_room_equipment[eqp] = {'status':request.form.get(eqp), 'remark':request.form.get(eqp+' remark')}
        channels_status = {}
        for channel in equipments.amhs_channel_list: 
            channels_status[channel] = {
            'during':request.form.get(channel+'_during'),
            'from':request.form.get(channel+'_from'),
            'to':request.form.get(channel+'_to'),
            'reason':request.form.get(channel+'_reason'),
            'end':request.form.get(channel+'_end')
            }
        attachments = result['attachments']
        for i in range (1, 100):
            if 'attachments_'+str(i) in request.files:
                attachments['title'].append(request.form.get('title_'+str(i)))
                file = request.files['attachments_'+str(i)]
                filename1 = secure_filename(file.filename)
                    #if allowed_file(filename1):
                file.save(os.path.join(app.config['ATTACHED_FILE_FOLDER'], filename1))
                file_type  = filename1.rsplit('.', 1)[1].lower()
                #opened_file = open(app.config['ATTACHED_FILE_FOLDER']+'/'+filename1, 'rb').read()
                directory = app.config['ATTACHED_FILE_FOLDER']+'/'+'amhs log no '+str(session['amhs_log_no'])
                if not os.path.exists(directory):
                    os.makedirs(directory)
                os.rename(app.config['ATTACHED_FILE_FOLDER']+'/'+filename1,
                    directory+'/'+request.form.get('title_'+str(i))+'.'+ file_type)
                attachments['attached_file_type'].append(file_type)
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
            'room_temp': request.form.get('room_temp'),
            'server_room_equipment': server_room_equipment,
            'channels_status': channels_status,
            'fpl': request.form.get('fpl'),
            'dla': request.form.get('dla'),
            'chg': request.form.get('chg'),
            'remarks': request.form.get('remarks').split("\n"),
            'attachments': attachments
            }
            }
            )
        update_signature = amhs_cursor.records.find_one({"id": int(id_no)})
        update_signature_path=[]
        od = update_signature['on_duty'] if update_signature['on_duty'][0] else []
        ov = update_signature['overtime'] if update_signature['overtime'][0] else []
        for initial in od+ov:
            signature_result = users_cursor.users.find_one({'initial': initial})
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
                {"id": int(id_no)},
                {'$set': {'signature_path': update_signature_path}}
                )
        flash('Saved Successfuly!', 'success')
        return redirect(url_for('amhs_log', id_no=int(id_no)))

    return render_template('index.html',
        navigator="edit amhs logs",
        title='edit amhs log number '+ id_no,
        log_no=int(id_no),
        result = result,
        channel_list=equipments.amhs_channel_list,
        server_room_eqp=equipments.amhs_server_room_eqp,
        msg_list=equipments.amhs_msg_list,
        log_records_list=session['log_records_list'],
        notam_data=notam_data,
        perm_data=perm_data,
        attachments=attachments_path_list
        )

@app.route('/it log form', methods=['GET', 'POST'])
@token_required
def it_log_form():
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    if not session['IT form']:
        flash('You Have not Permission to Fill out the Log!', 'error')
        return redirect(request.referrer)

    users_result = users_cursor.users.find({'department': 'Aeronautical Information and Communication Technology'})
    AICT_personel = []
    for r in users_result:
        AICT_personel.append(r['first_name']+' '+r['last_name'])
    result = amhs_cursor.it_records.find_one({"id": amhs_cursor.it_records.estimated_document_count()})
    wd = datetime.datetime.utcnow().weekday()
    session['datetime'] = datetime.datetime.utcnow().strftime('%Y - %m - %d')
    session['jdatetime'] = jdatetime.datetime.now().strftime('%Y - %m - %d')
    today = session['datetime']
    today_wd = utils.fetch_day(str(wd+1))

    if result:
        if (today==result['shift_date']):
            logdata = result
        else:
            logdata = None
            record = {'event_date': datetime.datetime.utcnow()}
            if amhs_cursor.it_records.estimated_document_count():
                record['id'] = amhs_cursor.it_records.estimated_document_count()+1
            else:
                record['id'] = 1
            record['shift_date'] = session['datetime']
            record['shift_jdate'] = session['jdatetime']
            record['present_members'] = request.form.getlist('present_members')
            record['day'] = today_wd
            record['team'] = ''
            record['checked'] = False
            amhs_cursor.it_records.insert_one(record)
            session['it_log_no'] = amhs_cursor.it_records.estimated_document_count()
            session['log_records_list'].insert(6, record['present_members'])
    else:
        logdata = None
        record = {'event_date': datetime.datetime.utcnow()}
        if amhs_cursor.it_records.estimated_document_count():
            record['id'] = amhs_cursor.it_records.estimated_document_count()+1
        else:
            record['id'] = 1
        record['shift_date'] = session['datetime']
        record['shift_jdate'] = session['jdatetime']
        record['present_members'] = request.form.getlist('present_members')
        record['day'] = today_wd
        record['team'] = ''
        record['checked'] = False
        amhs_cursor.it_records.insert_one(record)
        session['it_log_no'] = amhs_cursor.it_records.estimated_document_count()
        session['log_records_list'].insert(6, record['present_members'])

    presents_signature_path=[]
    for name in request.form.getlist('present_members'):
        name = name.split(' ')
        signature_result = users_cursor.users.find_one({'first_name':name[0], 'last_name':name[1]})
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
        presents_signature_path.append(initial_signature)

    if request.method == 'POST':
        amhs_cursor.it_records.update_many(
            {"id": session['it_log_no']},
            {'$set': {
            'id': session['it_log_no'],
            'present_members': request.form.getlist('present_members'),
            'team': request.form.get('team'),
            'day': request.form.get('day'),
            'remarks': request.form.get('remarks').split("\n"),
            'presents_signature_path': presents_signature_path
            }
            }
            )
        flash('Saved Successfuly!', 'success')
        session['log_records_list'].insert(6, request.form.getlist('present_members'))
        return redirect(url_for('it_log_form'))

    return render_template('index.html',
        navigator="it log form",
        title='it log form',
        nav='',
        log_no=session['amhs_log_no'],
        wd=today_wd,
        result = logdata,
        log_records_list=session['log_records_list'],
        AICT_personel=AICT_personel
        )

@app.route('/it forms/<form_number>', methods=['GET', 'POST'])
@token_required
def it_forms(form_number):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    if not session['IT form']:
        flash('You Have not Permission to Fill out the Log!', 'error')
        return redirect(request.referrer)

    result = amhs_cursor.it_records.find_one({"id": amhs_cursor.it_records.estimated_document_count()})
    logdata = result if result else None
    
    data_center_cooling = equipments.data_center_cooling
    data_center_server_rack = equipments.data_center_server_rack
    data_center_switching_rack = equipments.data_center_switching_rack
    data_center_fiber_optic_rack = equipments.data_center_fiber_optic_rack
    data_center_transmission_rack = equipments.data_center_transmission_rack
    data_center_communication_rack = equipments.data_center_communication_rack
    data_center_power_room = equipments.data_center_power_room
    dep_term_cooling = equipments.dep_term_cooling
    dep_term_server_rack = equipments.dep_term_server_rack
    dep_term_switching_rack = equipments.dep_term_switching_rack
    int_term_cooling = equipments.int_term_cooling
    int_term_rack_1 = equipments.int_term_rack_1
    office_bld_cooling = equipments.office_bld_cooling
    office_bld_rack_1 = equipments.office_bld_rack_1
    tech_block_ups = equipments.tech_block_ups
    tech_block_rack_1 = equipments.tech_block_rack_1
    fids_system = equipments.fids_system
    dc_antivirus = {'com_name':[], 'username':[], 'remark':[]}

    if form_number == 'i101':
        nav = "i101"
    elif form_number == 'i102':
        nav = "i102"
    elif form_number == 'i103':
        nav = "i103"
    elif form_number == 'i104':
        nav = "i104"
    elif form_number == 'i105':
        nav = "i105"
    else:
        flash('No Such Form!', 'error')
        return redirect(request.referrer)

    if request.method == 'POST':
        if form_number == 'i101':
            dc_inspector = request.form.get('dc inspector')
            dc_inspection_time = request.form.get('dc inspection_time')
            dc_remark = request.form.get('dc remark')
            dc_room_temp = request.form.get('dc room_temp')
            dc_cooling = {}
            for eqp in data_center_cooling: 
                dc_cooling[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_server_rack = {}
            for eqp in data_center_server_rack: 
                dc_server_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_switching_rack = {}
            for eqp in data_center_switching_rack: 
                dc_switching_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_fiber_optic_rack = {}
            for eqp in data_center_fiber_optic_rack: 
                dc_fiber_optic_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_no_active_equipment = request.form.get('dc No Active Equipment')
            dc_fiber_optic_remark = request.form.get('dc fiber optic remark')
            dc_transmission_rack = {}
            for eqp in data_center_transmission_rack: 
                dc_transmission_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_communication_rack = {}
            for eqp in data_center_communication_rack: 
                dc_communication_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_power_room_temp = request.form.get('dc power_room_temp')
            dc_power_room = {}
            for eqp in data_center_power_room: 
                dc_power_room[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            for i in range (100):
                if request.form.get('dc com_name_'+str(i)):
                    dc_antivirus['com_name'].append(request.form.get('dc com_name_'+str(i)))
                    dc_antivirus['username'].append(request.form.get('dc username_'+str(i)))
                    dc_antivirus['remark'].append(request.form.get('dc antevirus_remark_'+str(i)))
            amhs_cursor.it_records.update_many(
                {"id": session['it_log_no']},
                {'$set': {
                'id': session['it_log_no'],
                'data_center_inspector': dc_inspector,
                'data_center_inspection_time': dc_inspection_time,
                'data_center_remark': dc_remark,
                'data_center_room_temp': dc_room_temp,
                'data_center_cooling': dc_cooling,
                'data_center_server_rack': dc_server_rack,
                'data_center_switching_rack': dc_switching_rack,
                'data_center_fiber_optic_rack': dc_fiber_optic_rack,
                'data_center_no_active_equipment': dc_no_active_equipment,
                'data_center_fiber_optic_remark': dc_fiber_optic_remark,
                'data_center_transmission_rack': dc_transmission_rack,
                'data_center_communication_rack': dc_communication_rack,
                'data_center_power_room_temp': dc_power_room_temp,
                'data_center_power_room': dc_power_room,
                'data_center_antivirus': dc_antivirus
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('it_log_form'))
        elif form_number == 'i102':
            dt_inspector = request.form.get('dep_term inspector')
            dt_inspection_time = request.form.get('dep_term inspection_time')
            dt_remark = request.form.get('dep_term remark')
            dt_cooling = {}
            for eqp in dep_term_cooling: 
                dt_cooling[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_server_rack = {}
            for eqp in dep_term_server_rack: 
                dt_server_rack[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_switching_rack = {}
            for eqp in dep_term_switching_rack: 
                dt_switching_rack[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_fids_system = {}
            for eqp in fids_system: 
                dt_fids_system[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": session['it_log_no']},
                {'$set': {
                'id': session['it_log_no'],
                'dep_term_inspector': dt_inspector,
                'dep_term_inspection_time': dt_inspection_time,
                'dep_term_remark': dt_remark,
                'dep_term_cooling': dt_cooling,
                'dep_term_server_rack': dt_server_rack,
                'dep_term_switching_rack': dt_switching_rack,
                'dep_term_fids_system': dt_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('it_log_form'))
        elif form_number == 'i103':
            it_inspector = request.form.get('int_term inspector')
            it_inspection_time = request.form.get('int_term inspection_time')
            it_remark = request.form.get('int_term remark')
            it_room_temp = request.form.get('int_term room_temp')
            it_cooling = {}
            for eqp in int_term_cooling: 
                it_cooling[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            it_rack_1 = {}
            for eqp in int_term_rack_1: 
                it_rack_1[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            it_fids_system = {}
            for eqp in fids_system: 
                it_fids_system[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": session['it_log_no']},
                {'$set': {
                'id': session['it_log_no'],
                'int_term_inspector': it_inspector,
                'int_term_inspection_time': it_inspection_time,
                'int_term_remark': it_remark,
                'int_term_room_temp': it_room_temp,
                'int_term_cooling': it_cooling,
                'int_term_rack_1': it_rack_1,
                'int_term_fids_system': it_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('it_log_form'))
        elif form_number == 'i104':
            ob_inspector = request.form.get('office_bld inspector')
            ob_inspection_time = request.form.get('office_bld inspection_time')
            ob_remark = request.form.get('office_bld remark')
            ob_cooling = {}
            for eqp in office_bld_cooling: 
                ob_cooling[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            ob_rack_1 = {}
            for eqp in office_bld_rack_1: 
                ob_rack_1[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            ob_fids_system = {}
            for eqp in fids_system: 
                ob_fids_system[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": session['it_log_no']},
                {'$set': {
                'id': session['it_log_no'],
                'office_bld_inspector': ob_inspector,
                'office_bld_inspection_time': ob_inspection_time,
                'office_bld_remark': ob_remark,
                'office_bld_cooling': ob_cooling,
                'office_bld_rack_1': ob_rack_1,
                'office_bld_fids_system': ob_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('it_log_form'))
        elif form_number == 'i105':
            tb_inspector = request.form.get('tech_block inspector')
            tb_inspection_time = request.form.get('tech_block inspection_time')
            tb_remark = request.form.get('tech_block remark')
            tb_ups = {}
            for eqp in tech_block_ups: 
                tb_ups[eqp] = {'status':request.form.get('tech_block '+eqp), 'remark':request.form.get('tech_block '+eqp+' remark')}
            tb_rack_1 = {}
            for eqp in tech_block_rack_1:
                tb_rack_1[eqp] = {'status':request.form.get('tech_block '+eqp), 'remark':request.form.get('tech_block '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": session['it_log_no']},
                {'$set': {
                'id': session['it_log_no'],
                'tech_block_inspector': tb_inspector,
                'tech_block_inspection_time': tb_inspection_time,
                'tech_block_remark': tb_remark,
                'tech_block_ups': tb_ups,
                'tech_block_rack_1': tb_rack_1
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('it_log_form'))

    return render_template('index.html',
        navigator="it log form",
        title='it form '+ nav,
        nav=nav,
        result=logdata,
        data_center_cooling = equipments.data_center_cooling,
        data_center_server_rack = equipments.data_center_server_rack,
        data_center_switching_rack = equipments.data_center_switching_rack,
        data_center_fiber_optic_rack = equipments.data_center_fiber_optic_rack,
        data_center_transmission_rack = equipments.data_center_transmission_rack,
        data_center_communication_rack = equipments.data_center_communication_rack,
        data_center_power_room = equipments.data_center_power_room,
        dep_term_cooling = equipments.dep_term_cooling,
        dep_term_server_rack = equipments.dep_term_server_rack,
        dep_term_switching_rack = equipments.dep_term_switching_rack,
        int_term_cooling = equipments.int_term_cooling,
        int_term_rack_1 = equipments.int_term_rack_1,
        office_bld_cooling = equipments.office_bld_cooling,
        office_bld_rack_1 = equipments.office_bld_rack_1,
        tech_block_ups = equipments.tech_block_ups,
        tech_block_rack_1 = equipments.tech_block_rack_1,
        fids_system = equipments.fids_system,
        log_records_list=session['log_records_list']
        )

@app.route('/it logs/<id_no>/<form_number>', methods=['GET', 'POST'])
@token_required
def it_logs(id_no, form_number):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    result = amhs_cursor.it_records.find_one({"id": int(id_no)})
    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)

    users_result = users_cursor.users.find_one({'username': session['username']})
    if users_result:
        name = users_result['first_name']+' '+users_result['last_name']
    else:
        name = None

    if form_number == 'i101':
        nav = "i101"
    elif form_number == 'i102':
        nav = "i102"
    elif form_number == 'i103':
        nav = "i103"
    elif form_number == 'i104':
        nav = "i104"
    elif form_number == 'i105':
        nav = "i105"
    else:
        nav = ""

    return render_template('index.html',
        navigator="it logs",
        title='it log number '+id_no,
        log_no=int(id_no),
        nav=nav,
        result = result,
        name=name,
        data_center_cooling = equipments.data_center_cooling,
        data_center_server_rack = equipments.data_center_server_rack,
        data_center_switching_rack = equipments.data_center_switching_rack,
        data_center_fiber_optic_rack = equipments.data_center_fiber_optic_rack,
        data_center_transmission_rack = equipments.data_center_transmission_rack,
        data_center_communication_rack = equipments.data_center_communication_rack,
        data_center_power_room = equipments.data_center_power_room,
        dep_term_cooling = equipments.dep_term_cooling,
        dep_term_server_rack = equipments.dep_term_server_rack,
        dep_term_switching_rack = equipments.dep_term_switching_rack,
        int_term_cooling = equipments.int_term_cooling,
        int_term_rack_1 = equipments.int_term_rack_1,
        office_bld_cooling = equipments.office_bld_cooling,
        office_bld_rack_1 = equipments.office_bld_rack_1,
        tech_block_ups = equipments.tech_block_ups,
        tech_block_rack_1 = equipments.tech_block_rack_1,
        fids_system = equipments.fids_system,
        log_records_list=session['log_records_list']
        )

@app.route('/it-ck/<id_no>')
@token_required
def it_ck(id_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
    result = amhs_cursor.it_records.find_one({"id": int(id_no)})
    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)        
    if not session['admin']:
        flash('You Have not Permission to Check the Log!', 'error')
        return redirect(request.referrer)
    amhs_cursor.it_records.update_many(
            {"id": int(id_no)},
            {'$set': {
            'id': int(id_no),
            'checked': True
            }})
    flash('Checked', 'success')
    if int(id_no) < session['it_log_no']:
        unchecked_log = amhs_cursor.it_records.find_one({"checked": False})
        if unchecked_log:
            return redirect(url_for('it_logs', id_no=unchecked_log['id'], form_number='all'))
        else:
            return redirect(url_for('it_logs', id_no=session['it_log_no'], form_number='all'))
    else:
        return redirect(url_for('it_logs', id_no=session['it_log_no'], form_number='all'))

@app.route('/it logs/<id_no>/<form_number>/edit', methods=['GET', 'POST'])
@token_required
def edit_it_log(id_no, form_number):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)

    result = amhs_cursor.it_records.find_one({"id": int(id_no)})

    if not result:
        flash('No Such Result!', 'error')
        return redirect(request.referrer)

    this_user = users_cursor.users.find_one({'username': session['username']})
    name = this_user['first_name']+' '+this_user['last_name']
        
    if (not session['IT form']) or (name not in result['present_members']):
        flash('You Have not Permission to Edit the Log!', 'error')
        return redirect(request.referrer)

    users_result = users_cursor.users.find({'department': 'Aeronautical Information and Communication Technology'})
    AICT_personel = []
    for r in users_result:
        AICT_personel.append(r['first_name']+' '+r['last_name'])

    if form_number == 'i101': 
        nav = "i101"
    elif form_number == 'i102':
        nav = "i102"
    elif form_number == 'i103':
        nav = "i103"
    elif form_number == 'i104':
        nav = "i104"
    elif form_number == 'i105':
        nav = "i105"
    elif form_number == 'info':
        nav = "info"

    data_center_cooling = equipments.data_center_cooling
    data_center_server_rack = equipments.data_center_server_rack
    data_center_switching_rack = equipments.data_center_switching_rack
    data_center_fiber_optic_rack = equipments.data_center_fiber_optic_rack
    data_center_transmission_rack = equipments.data_center_transmission_rack
    data_center_communication_rack = equipments.data_center_communication_rack
    data_center_power_room = equipments.data_center_power_room
    dep_term_cooling = equipments.dep_term_cooling
    dep_term_server_rack = equipments.dep_term_server_rack
    dep_term_switching_rack = equipments.dep_term_switching_rack
    int_term_cooling = equipments.int_term_cooling
    int_term_rack_1 = equipments.int_term_rack_1
    office_bld_cooling = equipments.office_bld_cooling
    office_bld_rack_1 = equipments.office_bld_rack_1
    tech_block_ups = equipments.tech_block_ups
    tech_block_rack_1 = equipments.tech_block_rack_1
    fids_system = equipments.fids_system
    dc_antivirus = {'com_name':[], 'username':[], 'remark':[]}

    if request.method == 'POST':
        if form_number == 'info':
            presents_signature_path=[]
            for name in request.form.getlist('present_members'):
                name = name.split(' ')
                signature_result = users_cursor.users.find_one({'first_name':name[0], 'last_name':name[1]})
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
                presents_signature_path.append(initial_signature)
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'present_members': request.form.getlist('present_members'),
                'team': request.form.get('team'),
                'day': request.form.get('day'),
                'remarks': request.form.get('remarks').split("\n"),
                'presents_signature_path': presents_signature_path
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            if int(id_no) == session['it_log_no']:
                session['log_records_list'].insert(6, request.form.getlist('present_members'))
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
        if form_number == 'i101':
            dc_inspector = request.form.get('dc inspector')
            dc_inspection_time = request.form.get('dc inspection_time')
            dc_remark = request.form.get('dc remark')
            dc_room_temp = request.form.get('dc room_temp')
            dc_cooling = {}
            for eqp in data_center_cooling: 
                dc_cooling[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_server_rack = {}
            for eqp in data_center_server_rack: 
                dc_server_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_switching_rack = {}
            for eqp in data_center_switching_rack: 
                dc_switching_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_fiber_optic_rack = {}
            for eqp in data_center_fiber_optic_rack: 
                dc_fiber_optic_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_no_active_equipment = request.form.get('dc No Active Equipment')
            dc_fiber_optic_remark = request.form.get('dc fiber optic remark')
            dc_transmission_rack = {}
            for eqp in data_center_transmission_rack: 
                dc_transmission_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_communication_rack = {}
            for eqp in data_center_communication_rack: 
                dc_communication_rack[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            dc_power_room_temp = request.form.get('dc power_room_temp')
            dc_power_room = {}
            for eqp in data_center_power_room: 
                dc_power_room[eqp] = {'status':request.form.get('dc '+eqp), 'remark':request.form.get('dc '+eqp+' remark')}
            for i in range (100):
                if request.form.get('dc com_name_'+str(i)):
                    dc_antivirus['com_name'].append(request.form.get('dc com_name_'+str(i)))
                    dc_antivirus['username'].append(request.form.get('dc username_'+str(i)))
                    dc_antivirus['remark'].append(request.form.get('dc antevirus_remark_'+str(i)))
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'data_center_inspector': dc_inspector,
                'data_center_inspection_time': dc_inspection_time,
                'data_center_remark': dc_remark,
                'data_center_room_temp': dc_room_temp,
                'data_center_cooling': dc_cooling,
                'data_center_server_rack': dc_server_rack,
                'data_center_switching_rack': dc_switching_rack,
                'data_center_fiber_optic_rack': dc_fiber_optic_rack,
                'data_center_no_active_equipment': dc_no_active_equipment,
                'data_center_fiber_optic_remark': dc_fiber_optic_remark,
                'data_center_transmission_rack': dc_transmission_rack,
                'data_center_communication_rack': dc_communication_rack,
                'data_center_power_room_temp': dc_power_room_temp,
                'data_center_power_room': dc_power_room,
                'data_center_antivirus': dc_antivirus
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
        elif form_number == 'i102':
            dt_inspector = request.form.get('dep_term inspector')
            dt_inspection_time = request.form.get('dep_term inspection_time')
            dt_remark = request.form.get('dep_term remark')
            dt_cooling = {}
            for eqp in dep_term_cooling: 
                dt_cooling[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_server_rack = {}
            for eqp in dep_term_server_rack: 
                dt_server_rack[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_switching_rack = {}
            for eqp in dep_term_switching_rack: 
                dt_switching_rack[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            dt_fids_system = {}
            for eqp in fids_system: 
                dt_fids_system[eqp] = {'status':request.form.get('dep_term '+eqp), 'remark':request.form.get('dep_term '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'dep_term_inspector': dt_inspector,
                'dep_term_inspection_time': dt_inspection_time,
                'dep_term_remark': dt_remark,
                'dep_term_cooling': dt_cooling,
                'dep_term_server_rack': dt_server_rack,
                'dep_term_switching_rack': dt_switching_rack,
                'dep_term_fids_system': dt_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
        elif form_number == 'i103':
            it_inspector = request.form.get('int_term inspector')
            it_inspection_time = request.form.get('int_term inspection_time')
            it_remark = request.form.get('int_term remark')
            it_room_temp = request.form.get('int_term room_temp')
            it_cooling = {}
            for eqp in int_term_cooling: 
                it_cooling[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            it_rack_1 = {}
            for eqp in int_term_rack_1: 
                it_rack_1[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            it_fids_system = {}
            for eqp in fids_system: 
                it_fids_system[eqp] = {'status':request.form.get('int_term '+eqp), 'remark':request.form.get('int_term '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'int_term_inspector': it_inspector,
                'int_term_inspection_time': it_inspection_time,
                'int_term_remark': it_remark,
                'int_term_room_temp': it_room_temp,
                'int_term_cooling': it_cooling,
                'int_term_rack_1': it_rack_1,
                'int_term_fids_system': it_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
        elif form_number == 'i104':
            ob_inspector = request.form.get('office_bld inspector')
            ob_inspection_time = request.form.get('office_bld inspection_time')
            ob_remark = request.form.get('office_bld remark')
            ob_cooling = {}
            for eqp in office_bld_cooling: 
                ob_cooling[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            ob_rack_1 = {}
            for eqp in office_bld_rack_1: 
                ob_rack_1[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            ob_fids_system = {}
            for eqp in fids_system: 
                ob_fids_system[eqp] = {'status':request.form.get('office_bld '+eqp), 'remark':request.form.get('office_bld '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'office_bld_inspector': ob_inspector,
                'office_bld_inspection_time': ob_inspection_time,
                'office_bld_remark': ob_remark,
                'office_bld_cooling': ob_cooling,
                'office_bld_rack_1': ob_rack_1,
                'office_bld_fids_system': ob_fids_system
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
        elif form_number == 'i105':
            tb_inspector = request.form.get('tech_block inspector')
            tb_inspection_time = request.form.get('tech_block inspection_time')
            tb_remark = request.form.get('tech_block remark')
            tb_ups = {}
            for eqp in tech_block_ups: 
                tb_ups[eqp] = {'status':request.form.get('tech_block '+eqp), 'remark':request.form.get('tech_block '+eqp+' remark')}
            tb_rack_1 = {}
            for eqp in tech_block_rack_1:
                tb_rack_1[eqp] = {'status':request.form.get('tech_block '+eqp), 'remark':request.form.get('tech_block '+eqp+' remark')}
            amhs_cursor.it_records.update_many(
                {"id": int(id_no)},
                {'$set': {
                'id': int(id_no),
                'tech_block_inspector': tb_inspector,
                'tech_block_inspection_time': tb_inspection_time,
                'tech_block_remark': tb_remark,
                'tech_block_ups': tb_ups,
                'tech_block_rack_1': tb_rack_1
                }
                }
                )
            flash('Saved Successfuly!', 'success')
            return redirect(url_for('edit_it_log', id_no=id_no, form_number=form_number))
    
    return render_template('index.html',
        navigator = "it log form",
        title='edit it log number '+id_no,
        log_no=int(id_no),
        nav=nav,
        wd=result['day'],
        result=result,
        data_center_cooling = equipments.data_center_cooling,
        data_center_server_rack = equipments.data_center_server_rack,
        data_center_switching_rack = equipments.data_center_switching_rack,
        data_center_fiber_optic_rack = equipments.data_center_fiber_optic_rack,
        data_center_transmission_rack = equipments.data_center_transmission_rack,
        data_center_communication_rack = equipments.data_center_communication_rack,
        data_center_power_room = equipments.data_center_power_room,
        dep_term_cooling = equipments.dep_term_cooling,
        dep_term_server_rack = equipments.dep_term_server_rack,
        dep_term_switching_rack = equipments.dep_term_switching_rack,
        int_term_cooling = equipments.int_term_cooling,
        int_term_rack_1 = equipments.int_term_rack_1,
        office_bld_cooling = equipments.office_bld_cooling,
        office_bld_rack_1 = equipments.office_bld_rack_1,
        tech_block_ups = equipments.tech_block_ups,
        tech_block_rack_1 = equipments.tech_block_rack_1,
        fids_system = equipments.fids_system,
        AICT_personel=AICT_personel,
        log_records_list=session['log_records_list']
        )

@app.route('/fids/<airport>/<arr_dep>', methods=['GET', 'POST'])
@token_required
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
        title='fids '+airport,
        airport=airport,
        arr_dep=arr_dep,
        log_records_list=session['log_records_list'],
        s=l,
        en_name=en_name
        )

@app.route('/adsb/<airport>')
@token_required
def adsb(airport):
    #adsb_cursor = utils.config_mongodb("172.27.13.68", 27017, 'ADSB-BL')
    rule = request.url_rule
    if session['adsb_db']:
        location = session['adsb_db']
    else:        
        location = [
        {
            'icon': 'http://maps.google.com/mapfiles/ms/icons/green-dot.png',
            'lat': 34.345853,
            'lng': 47.158128,
            'infobox': "<b>Mehrabad Airport</b>"
        }
        ]
    
    airport = Map(
        identifier="airport",
        lat = 34.345853,
        lng = 47.158128,
        style = "height:79vh;width:62vw;margin:-8px 0 0 0;",
        zoom = 8,
        maptype = "TERRAIN",
        fullscreen_control=False,
        markers = [{'icon': location[i]['icon'], 'lat':location[i]['lat'] ,
        'lng':location[i]['lng'] , 'infobox':location[i]['infobox']} for i in range(len(location))]
    )

    return render_template('index.html',
        navigator="map",
        title='map '+airport,
        log_records_list=session['log_records_list'],
        airport=airport
    )

@app.route('/adsb/<airport>/get data')
@token_required
def adsb_get_data(airport):
    adsb_cursor = utils.config_mongodb("172.27.13.68", 27017, 'ADSB-BL')
    rule = request.url_rule
    location = [
    {
        'icon': 'http://maps.google.com/mapfiles/ms/icons/green-dot.png',
        'lat': 34.345853,
        'lng': 47.158128,
        'infobox': "<b>Kermanshah Airport</b>"
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
        flash("Successful!", "success")
    else:
        flash("your data can not be fetched", "error")
    
    airport = Map(
        identifier="airport",
        lat = 34.345853,
        lng = 47.158128,
        style = "height:79vh;width:62vw;margin:-8px 0 0 0;",
        zoom = 8,
        maptype = "TERRAIN",
        fullscreen_control=False
    )

    return render_template('index.html',
        navigator="map",
        title='map '+airport,
        log_records_list=session['log_records_list'],
        airport=airport
    )

@app.route('/New Message/<msg_type>/<log_no>', methods=['GET', 'POST'])
@token_required
def new_message(msg_type, log_no):
    
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    if not session['AMHS form']:
        flash('You Have not Permission to Fill out the Log!', 'error')
        return redirect(request.referrer)
    
    new_msg = {}
    if request.method == 'POST':
        print('POST')
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
            if processed_perm == "Invalid Permission Referece!":
                flash('Invalid Permission Referece! Please Check the Message.', 'error')
                return redirect(request.referrer)
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

    return render_template('includes/_newNotamPermMessage.html', title='new message')

@app.route('/Notam/<notam_no>')
@token_required
def notam(notam_no):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    #if not session['AMHS form']:
        #flash('You Have not Permission to Fill out the Log!', 'error')
        #return redirect(request.referrer)
    
    notam_no = notam_no.replace('-', '/')
    result_notam = amhs_cursor.notam.find_one({"notam_no": notam_no})
    notam_msg = result_notam['full_message']
    return render_template('includes/_notampermMessage.html', msg=notam_msg, title='notam '+notam_no)

@app.route('/Permission/<id_num>/<tsa>/<ref>/<granted>')
@token_required
def permission(id_num, tsa, ref, granted):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    #if not session['AMHS form']:
        #flash('You Have not Permission to Fill out the Log!', 'error')
        #return redirect(request.referrer)
    
    if "not found" not in ref:
        ref = ref.replace('-', '/')
        result_permission = amhs_cursor.permission.find_one({"perm_ref": ref, "granted":granted})
    else:
        result_permission = amhs_cursor.permission.find_one({"id": int(id_num), "tsa": tsa, "granted":granted})
    perm_msg = result_permission['full_message']
    return render_template('includes/_notampermMessage.html', msg=perm_msg, title='permission '+ref)

@app.route('/Delete/<id_num>/<tsa>/<indicator>')
@token_required
def delete(id_num, tsa, indicator):
    if 'username' not in session:
        flash('Please Sign in First!', 'error')
        return redirect(request.referrer)
        
    if not session['AMHS form']:
        flash('You Have not Permission to Fill out the Log!', 'error')
        return redirect(request.referrer)
    
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
    return render_template('500.html', title='error'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug = True)
