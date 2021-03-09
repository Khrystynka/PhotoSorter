
from flask import render_template, url_for, flash, redirect,jsonify,make_response,session,json,jsonify
from flask import request
from server.models import User, Upload,Tag
from server import app,db,bcrypt,gcs,bucket,jwt
from flask_jwt_extended import get_jwt
from datetime import datetime
from datetime import timedelta
# from flask_login import login_user,current_user,logout_user
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required,current_user
from flask_jwt_extended import create_refresh_token



import os
import uuid

from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
TOKEN_EXPIRES = 15
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Register a callback function that loades a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()



@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="dave", err="Your token has expired.Login again!"), 401

@app.route('/upload', methods=['GET','POST'])
@jwt_required()
def upload():
    print('before upload current user',current_user)
    print ('files in rewuest',request.files, 'form', request.form,'form keys',request.form.keys,'form values',request.form.values)
    file = request.files.get('file')
    alltags = (request.form['tags']).split(',')
    print(alltags)
    print('all files', file)
    print ('another data',request.form)
    if not file or not allowed_file(file.filename):
            return jsonify("No file Upploaded")
    upload_dict={}
    print(file,file.name,file.filename)
    originalfilename = secure_filename(file.filename)
    new_filename = str(uuid.uuid4())
    upload_dict[new_filename]=originalfilename
    blob = bucket.blob(new_filename)
    blob.upload_from_string(file.read(),content_type=file.content_type)
    # blob.upload_from_filename(server_path)
    print(upload_dict)
    upload_entry = Upload(original_name=originalfilename, hash_name = new_filename,cloud_path=blob.public_url,user_id=current_user.id)
    upload_entry.tags=[]
    for tag_name in alltags:
        if tag_name!='':
            tag =Tag.query.filter_by(name=tag_name).first()
            if not tag:    
                tag=Tag(name=tag_name)
                db.session.add(tag)
                db.session.commit()

            upload_entry.tags.append(tag)
    db.session.add(upload_entry)
    db.session.commit()
    check=Upload.query.filter(Upload.id==upload_entry.id,Upload.user_id==current_user.id).first()
    print('check tags for file',originalfilename,'from user',current_user.username,current_user.id,'are', check.tags)
    print('after upload current user',current_user, current_user.is_authenticated)
        
    return jsonify({"upload_id":upload_entry.id, 'gc_url':upload_entry.cloud_path})


@app.route('/login', methods=['GET','POST'])
def login():
    form_email = request.json['email']
    form_password=request.json['password']

    user = User.query.filter_by(email=form_email).first()
    if not user or not bcrypt.check_password_hash(user.password, form_password):
            return jsonify("Wrong username or password"), 401

    access_token = create_access_token(identity=user)
    refresh_token = create_refresh_token(identity=user)
    
    print('access token details', access_token)
    return jsonify(
        {
            "access_token":access_token,
            "refresh_token":refresh_token,
            "user_id":user.id,
            "token_expires":TOKEN_EXPIRES
})

@app.route('/register', methods=['POST'])
def register():
    form_email = request.json['email']
    form_password=request.json['password']
    print(form_email,form_password)
    hashed_password=bcrypt.generate_password_hash(form_password).decode('utf-8')
    if User.query.filter_by(email=form_email).first():
                return jsonify("Username or email are not unique. Please select another one"), 401

    user_entry=User(username=form_email,password=hashed_password,email=form_email)
    db.session.add(user_entry)
    db.session.commit()
    access_token = create_access_token(identity=user_entry)
    refresh_token = create_refresh_token(identity=user_entry)

    return jsonify({
        "access_token":access_token,
        "refresh_token":refresh_token,
        "user_id":user_entry.id,
        "token_expires":TOKEN_EXPIRES

        
        })

# We are using the `refresh=True` options in jwt_required to only allow
# refresh tokens to access this route.
# $ http POST :5000/refresh Authorization:"Bearer $REFRESH_TOKEN"

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)
    return jsonify(access_token=access_token,refresh_token =refresh_token)


@app.route("/who_am_i", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
    )


@app.route('/logout', methods=['GET','POST'])
def logout():
    print('beforelogout',current_user, current_user.is_authenticated)
    # if current_user.is_authenticated:

        # logout_user()
    #     return "The user is already authenticated!"
    print('afterlogout',current_user, current_user.is_authenticated)

    return redirect(url_for('login'))
@app.route('/get_uploads', methods=['GET','POST'])
@jwt_required()
def get_uploads():
    
    uploads=Upload.query.filter_by(author=current_user).all()            
    upload_list=[{
        'id':(upload.id),
        'user_id':current_user.id,
        'title':upload.original_name,
        'url':upload.cloud_path,
        'tags':[tag.name for tag in upload.tags]} 
        for upload in uploads]
    print('sending beck user docs',upload_list)
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
@app.route('/modify_tags', methods=['GET','POST'])
@jwt_required()
def add_tag():
    print('request',request)
    new_tags = request.json['tags']
    file_id= request.json['documentId']
    print('from server modify tags',new_tags,file_id)
    upload= Upload.query.filter_by(id=file_id).first()
    if not upload:
        return jsonify("The file was not uploaded ")
    upload.tags=[]
    for tag_name in new_tags:
        tag = Tag.query.filter_by(name=tag_name ).first()
        if not tag:
            tag=Tag(name = tag_name)
        upload.tags.append(tag)
    db.session.add(upload)
    db.session.commit()
    # response = make_response(jsonify(list(tag_set)))
    # response.headers['Access-Control-Allow-Origin'] = 'null'
    # response.headers['Access-Control-Allow-Credentials']= 'true'
    return jsonify({'added tags':new_tags})

@app.route('/delete', methods=['GET','POST'])
@jwt_required()
def delete_document():
    print('from delete document',request)
    file_id= request.json['documentId']
    print('from server delete ',file_id)
    upload= Upload.query.filter_by(id=file_id).first()
    
    db.session.delete(upload)
    db.session.commit()
    return jsonify({'deleted document with id':file_id})

  # @app.route('/upload', methods=['GET', 'POST'])
# def upload():
#     print('before upload current user',current_user, current_user.is_authenticated)
#     if not current_user.is_authenticated:
#         redirect(url_for("login"))
#     if request.method=='GET':
#         return render_template("index.html")
    
#     if request.method == 'POST':
#         allfiles = request.files.getlist('file')
#         print('all files', allfiles)
#         print ('another data',request.form)
#         if len(allfiles) == 0:
#             return "No files Upploaded"
#         upload_dict={}
#         # Get the bucket that the file will be uploaded to.

#         # Create a new blob and upload the file's content.

#         for (index,file) in enumerate(allfiles):
#             if file and allowed_file(file.filename):
#                 originalfilename = secure_filename(file.filename)
#                 new_filename = str(uuid.uuid4())
#                 # server_path = os.path.join(
#                 #     app.config['UPLOAD_FOLDER'], new_filename)
#                 upload_dict[new_filename]=originalfilename
#                 # file.save(server_path)
#                 blob = bucket.blob(new_filename)
#                 blob.upload_from_string(file.read(),content_type=file.content_type)
#                 # blob.upload_from_filename(server_path)
#                 tag_name = request.form['tag'+str(index)]
#                 tag =Tag.query.filter_by(name=tag_name).first()
#                 if not tag:    
#                     tag=Tag(name=tag_name)
#                 upload_entry = Upload(original_name=originalfilename, hash_name = new_filename,cloud_path=blob.public_url,user_id=current_user.id)
#                 print('upload_entry',upload_entry,upload_entry.tags)
#                 upload_entry.tags.append(tag)
#                 db.session.add(upload_entry)
#                 db.session.add(tag)
#                 db.session.commit()
#                 check=Upload.query.filter(Upload.id==upload_entry.id,Upload.user_id==current_user.id).first()
#                 print('check tags for file',originalfilename,'from user',current_user.username,current_user.id,'are', check.tags)
#         # print('after upload current user',current_user, current_user.is_authenticated)
        
#         return jsonify(upload_dict)
#     return 'Something went wrong(('

# @app.route('/register', methods=["GET",'POST'])
# def register():
#     if request.method == "GET":
#         return render_template('register.html')
#     print('before register current user',current_user, current_user.is_authenticated)
#     # if current_user.is_authenticated:
#     #     return "The user is already authenticated!"
#     print("username",request.form['username'],'password',request.form['password'])
#     hashed_password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
#     if User.query.filter_by(username=request.form['username']).first() or User.query.filter_by(email=request.form['email']).first():
#             # flash( 'Username already taken.Please select another')
#             return "Username or email are not unique. Please select another one"
#     user_entry=User(username=request.form['username'],password=hashed_password,email=request.form['email'])
#     db.session.add(user_entry)
#     db.session.commit()
#     print('User entry id',user_entry.id)
#     return "Super"
# @app.route('/login', methods=['GET','POST'])
# def login():
#     print('beforelogin',current_user, current_user.is_authenticated)
#     # if current_user.is_authenticated:
#     #      return "The user is already authenticated!"
#     if request.method=='GET':
#         return render_template("login.html")

#     user = User.query.filter_by(username=request.form['username']).first()
#     if user and bcrypt.check_password_hash(user.password, request.form['password']):
#             # flash( 'Username already taken.Please select another')
#             login_user(user,remember = request.form['remember'])
#             return redirect(url_for('upload'))
#     else: 
#         return redirect(url_for('register'))
