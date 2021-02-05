
from flask import render_template, url_for, flash, redirect,jsonify,make_response,session
from flask import request
from server.models import User, Upload,Tag
from server import app,db,bcrypt,gcs,bucket
from flask_login import login_user,current_user,logout_user

import os
import uuid

from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload():
    print('before upload current user',current_user, current_user.is_authenticated)
    if not current_user.is_authenticated:
        redirect(url_for("login"))
    if request.method=='GET':
        return render_template("index.html")
    
    if request.method == 'POST':
        allfiles = request.files.getlist('file')
        print('all files', allfiles)
        print ('another data',request.form)
        if len(allfiles) == 0:
            return "No files Upploaded"
        upload_dict={}
        # Get the bucket that the file will be uploaded to.

        # Create a new blob and upload the file's content.

        for (index,file) in enumerate(allfiles):
            if file and allowed_file(file.filename):
                originalfilename = secure_filename(file.filename)
                new_filename = str(uuid.uuid4())
                # server_path = os.path.join(
                #     app.config['UPLOAD_FOLDER'], new_filename)
                upload_dict[new_filename]=originalfilename
                # file.save(server_path)
                blob = bucket.blob(new_filename)
                blob.upload_from_string(file.read(),content_type=file.content_type)
                # blob.upload_from_filename(server_path)
                tag_name = request.form['tag'+str(index)]
                tag =Tag.query.filter_by(name=tag_name).first()
                if not tag:    
                    tag=Tag(name=tag_name)
                upload_entry = Upload(original_name=originalfilename, hash_name = new_filename,cloud_path=blob.public_url,user_id=current_user.id)
                print('upload_entry',upload_entry,upload_entry.tags)
                upload_entry.tags.append(tag)
                db.session.add(upload_entry)
                db.session.add(tag)
                db.session.commit()
                check=Upload.query.filter(Upload.id==upload_entry.id,Upload.user_id==current_user.id).first()
                print('check tags for file',originalfilename,'from user',current_user.username,current_user.id,'are', check.tags)
        # print('after upload current user',current_user, current_user.is_authenticated)
        
        return jsonify(upload_dict)
    return 'Something went wrong(('

@app.route('/register', methods=["GET",'POST'])
def register():
    if request.method == "GET":
        return render_template('register.html')
    print('before register current user',current_user, current_user.is_authenticated)
    # if current_user.is_authenticated:
    #     return "The user is already authenticated!"
    print("username",request.form['username'],'password',request.form['password'])
    hashed_password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    if User.query.filter_by(username=request.form['username']).first() or User.query.filter_by(email=request.form['email']).first():
            # flash( 'Username already taken.Please select another')
            return "Username or email are not unique. Please select another one"
    user_entry=User(username=request.form['username'],password=hashed_password,email=request.form['email'])
    db.session.add(user_entry)
    db.session.commit()
    print('User entry id',user_entry.id)
    return "Super"
@app.route('/login', methods=['GET','POST'])
def login():
    print('beforelogin',current_user, current_user.is_authenticated)
    # if current_user.is_authenticated:
    #      return "The user is already authenticated!"
    if request.method=='GET':
        return render_template("login.html")

    user = User.query.filter_by(username=request.form['username']).first()
    if user and bcrypt.check_password_hash(user.password, request.form['password']):
            # flash( 'Username already taken.Please select another')
            login_user(user,remember = request.form['remember'])
            return redirect(url_for('upload'))
    else: 
        return redirect(url_for('register'))
@app.route('/logout', methods=['GET','POST'])
def logout():
    print('beforelogout',current_user, current_user.is_authenticated)
    if current_user.is_authenticated:
        logout_user()
    #     return "The user is already authenticated!"
    print('afterlogout',current_user, current_user.is_authenticated)

    return redirect(url_for('login'))
@app.route('/get_uploads', methods=['GET','POST'])
def get_uploads():
    print(current_user, current_user.is_authenticated)
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    uploads=Upload.query.filter_by(author=current_user).all()            
    upload_list=[upload.original_name for upload in uploads]
    return jsonify(upload_list)

@app.route('/get_tags', methods=['GET','POST'])
def tags():
    if not current_user.is_authenticated:
        redirect(url_for("login"))
    tag_set=set()
    uploads=Upload.query.filter_by(author=current_user).all()  
    print('uploads for current user', uploads)
    for upload in uploads:
        for tag in upload.tags:
            tag_set.add(tag.name)
    response = make_response(jsonify(list(tag_set)))
    # response.headers['Access-Control-Allow-Origin'] = 'null'
    # response.headers['Access-Control-Allow-Credentials']= 'true'
    return response

    # return jsonify(tag_list)
@app.route('/<file_hashname>/get_tags', methods=['GET','POST'])
def upload_tags(file_hashname):
    if not current_user.is_authenticated:
        redirect(url_for("login"))
    upload= Upload.query.filter_by(hash_name=file_hashname).first()
    if not upload:
        return "The file was not uploaded "
    if current_user!=upload.author:
        return "You are not authenticated to view this file"
    file_tags=[]
    for tag in upload.tags:
        file_tags.append(tag.name)
    # response = make_response(jsonify(list(tag_set)))
    # response.headers['Access-Control-Allow-Origin'] = 'null'
    # response.headers['Access-Control-Allow-Credentials']= 'true'
    return jsonify(file_tags)
@app.route('/<file_hashname>/modify_tags', methods=['GET','POST'])
def add_tag(file_hashname):
    if request.method == "GET":
        return render_template('modify_tags.html')
    else:
        print (request.form)
        return request.form
    print('request args',request.form.listvalues)
    print ("request qury string",request.query_string)
    # new_tags = request.form.listvalues
    new_tags=['family','vacation']
    if not current_user.is_authenticated:
        redirect(url_for("login"))
    upload= Upload.query.filter_by(hash_name=file_hashname).first()
    if not upload:
        return "The file was not uploaded "
    if current_user!=upload.author:
        return "You are not authenticated to view this file"
    for tag_name in new_tags:
        tag = Tag.query.filetr_by(name=tag_name ).first()
        if not tag:
            tag=Tag(name = tag_name)
        upload.tags.append(tag)
    db.session.add(upload)
    db.session.commit()
    # response = make_response(jsonify(list(tag_set)))
    # response.headers['Access-Control-Allow-Origin'] = 'null'
    # response.headers['Access-Control-Allow-Credentials']= 'true'
    return jsonify({'added tags':new_tags})

  