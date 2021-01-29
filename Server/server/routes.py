
from flask import render_template, url_for, flash, redirect,jsonify
from flask import request
from server.models import User, Upload
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
        return "Login first"
    if request.method == 'POST':
        allfiles = request.files.getlist('file')
        print(allfiles)
        if len(allfiles) == 0:
            return "No files Upploaded"
        # Get the bucket that the file will be uploaded to.

        # Create a new blob and upload the file's content.

        for file in allfiles:
            if file and allowed_file(file.filename):
                originalfilename = secure_filename(file.filename)
                new_filename = str(uuid.uuid4())
                # server_path = os.path.join(
                #     app.config['UPLOAD_FOLDER'], new_filename)

                # file.save(server_path)
                blob = bucket.blob(new_filename)
                blob.upload_from_string(file.read(),content_type=file.content_type)
                # blob.upload_from_filename(server_path)
                

                upload_entry = Upload(original_name=originalfilename, path=blob.public_url,user_id=current_user.id)
                db.session.add(upload_entry)
                db.session.commit()
            
        print('after upload current user',current_user, current_user.is_authenticated)
        
        return "Super"
    # blob = bucket.blob(uploaded_file.filename)


    # # The public URL can be used to directly access the uploaded file via HTTP.
    # return blob.public_url


        # if 'file' not in request.files:
        #     # return redirect(request.url)
        #     return 'No files'
        # file = request.files['file']
        # if file.filename == '':
        #     # return redirect(request.url)
        #     return 'No files'

        # if file and allowed_file(file.filename):
        #     filename = secure_filename(file.filename)
        #     print('secure filename', filename)
        #     print(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        #     # return redirect(url_for('uploaded_file',
        #     # filename=filename))

        # return 'Success!'

    return 'Something went wrong(('
@app.route('/register', methods=['POST'])
def register():
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
@app.route('/login', methods=['POST'])
def login():
    print('beforelogin',current_user, current_user.is_authenticated)
    # if current_user.is_authenticated:
    #     return "The user is already authenticated!"
    user = User.query.filter_by(username=request.form['username']).first()
    if user and bcrypt.check_password_hash(user.password, request.form['password']):
            # flash( 'Username already taken.Please select another')
            login_user(user,remember = request.form['remember'])
            print('current user sfter login',current_user,current_user.is_authenticated)
            return "User is successfully logged in!"
    return "Login unsuccessfull.Check everything"
@app.route('/logout', methods=['GET','POST'])
def logout():
    print('beforelogout',current_user, current_user.is_authenticated)
    if current_user.is_authenticated:
        logout_user()
    #     return "The user is already authenticated!"
    print('afterlogout',current_user, current_user.is_authenticated)

    return "Logged out user"
@app.route('/get_uploads', methods=['GET','POST'])
def get_uploads():
    print(current_user, current_user.is_authenticated)
    if not current_user.is_authenticated:
        return "Login first!"
    uploads=Upload.query.filter_by(author=current_user).all()            
    upload_list=[upload.original_name for upload in uploads]
    return jsonify(upload_list)
