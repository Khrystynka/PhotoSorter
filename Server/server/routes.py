
from flask import render_template, url_for, flash, redirect,jsonify,make_response,session,json,jsonify
from flask import request
from flask import Blueprint
from server.models import User, Upload,Tag
from server import db,bcrypt,gcs,bucket,jwt
from flask_jwt_extended import get_jwt
from datetime import datetime
from datetime import timedelta
from flask_login import login_user,current_user,logout_user
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required,current_user
from flask_jwt_extended import create_refresh_token
bp = Blueprint("routes", __name__)



import os
import uuid

from werkzeug.utils import secure_filename
import werkzeug

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
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
    return jsonify(err="Your token has expired.Login again!"), 401

@bp.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    try:
        file = request.files.get('file')
        alltags = (request.form['tags']).split(',')
        if not file or not allowed_file(file.filename):
            responseObject = {
                    'status': 'fail',
                    'message': 'File is not allowed.'
                }
            return make_response(jsonify(responseObject)), 404
        else:
            upload_dict={}
            originalfilename = secure_filename(file.filename)
            new_filename = str(uuid.uuid4())
            upload_dict[new_filename]=originalfilename
            blob = bucket.blob(new_filename)
            blob.upload_from_string(file.read(),content_type=file.content_type)
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
            responseObject = {
                    'status': 'success',
                    'message': 'File was successfully uploaded.',
                    "upload_id": upload_entry.id,
                    'gc_url':upload_entry.cloud_path
                }
            return make_response(jsonify(responseObject)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500



@bp.route('/login', methods=['POST'])
def login():
        post_data = request.get_json()
        access_token = None
        try:
            user = User.query.filter_by(email=post_data.get('email')).first()
            if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
                    access_token = create_access_token(identity=user)
                    refresh_token = create_refresh_token(identity=user)
            if access_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'access_token': access_token,
                        "refresh_token":refresh_token,
                        "user_id":user.id}
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist with provided credentials.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


@bp.route('/register', methods=['POST'])
def register():
    post_data = request.get_json()
    try:
        form_email = request.json['email']
        form_password=request.json['password']
        hashed_password = User.hash(form_password)
        if User.query.filter_by(email=form_email).first():
            responseObject = {
                'status': 'fail',
                'message': 'User email is already registered'
            }
            return make_response(jsonify(responseObject)), 404
        else:
            user_entry=User(username=form_email,password=hashed_password,email=form_email)
            db.session.add(user_entry)
            db.session.commit()
            access_token = create_access_token(identity=user_entry)
            refresh_token = create_refresh_token(identity=user_entry)
            responseObject = {
                'status': 'success',
                'message': 'User successfully registered!',
                "access_token":access_token,
                "refresh_token":refresh_token,
                "user_id":user_entry.id
            }
            return make_response(jsonify(responseObject)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

# We are using the `refresh=True` options in jwt_required to only allow
# refresh tokens to access this route.
# $ http POST :5000/refresh Authorization:"Bearer $REFRESH_TOKEN"

@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)
    return jsonify(access_token=access_token,refresh_token =refresh_token)


@bp.route("/who_am_i", methods=["GET"])
@jwt_required()
def decode_token():
    try:
        responseObject = {
                    'status': 'success',
                    'message': 'User successfully registered!',
                    'id':current_user.id,
                    'email':current_user.email,
                    'username':current_user.username,
                }
        return make_response(jsonify(responseObject)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


@bp.route('/get_uploads', methods=['GET','POST'])
@jwt_required()
def get_uploads():
    try:
        uploads=Upload.query.filter_by(author=current_user).all()            
        upload_list=[{
            'id':(upload.id),
            'user_id':current_user.id,
            'title':upload.original_name,
            'url':upload.cloud_path,
            'tags':[tag.name for tag in upload.tags]} 
            for upload in uploads]
        return make_response(jsonify(upload_list)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

@bp.route('/for_tag_get_uploads', methods=['GET','POST'])
@jwt_required()
def get_uploads_for_tag():
    try:
        tag_name = request.get_json()['tag']
        uploads=Upload.query.filter_by(author=current_user).all()            
        upload_list=[{
            'id':(upload.id),
            'user_id':current_user.id,
            'title':upload.original_name,
            'url':upload.cloud_path,
            'tags':[tag.name for tag in upload.tags]} 
            for upload in uploads if tag_name in [tag.name for tag in upload.tags]]
        return make_response(jsonify(upload_list)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


@bp.route('/get_tags', methods=['GET','POST'])
@jwt_required()
def tags():
    try:
        tag_set=set()
        uploads=Upload.query.filter_by(author=current_user).all()  
        for upload in uploads:
            for tag in upload.tags:
                tag_set.add(tag.name)
        return make_response(jsonify(list(tag_set))),200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

    # response.headers['Access-Control-Allow-Origin'] = 'null'
    # response.headers['Access-Control-Allow-Credentials']= 'true'

    # return jsonify(tag_list)
@bp.route('/<file_hashname>/get_tags', methods=['GET','POST'])
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
@bp.route('/modify_tags', methods=['GET','POST'])
@jwt_required()
def add_tag():
    try:
        new_tags = request.json['tags']
        file_id= request.json['documentId']
        upload= Upload.query.filter_by(id=file_id).first()
        if not upload:
            responseObject = {
                'status': 'fail',
                'message': 'The document is not uploaded to database'
            }
            return make_response(jsonify(responseObject)), 404
        else:
            upload.tags=[]
            for tag_name in new_tags:
                tag = Tag.query.filter_by(name=tag_name ).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                upload.tags.append(tag)
            db.session.add(upload)
            db.session.commit()
            responseObject = {
                    'status': 'success',
                    'message': 'Tags were successfully added to the document',
                    'added tags': new_tags
                }
            return make_response(jsonify(responseObject)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

@bp.route('/delete', methods=['GET','POST'])
@jwt_required()
def delete_document():
    try:
        file_id= request.json['documentId']
        upload= Upload.query.filter_by(id=file_id).first()
        db.session.delete(upload)
        db.session.commit()
        responseObject = {
                    'status': 'success',
                    'message': 'The document was successfully deleted!',
                    'deleted document id': file_id
                }
        return make_response(jsonify(responseObject)), 200
    except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


@bp.route('/get_user/<email>')
def get_user(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        return 'No user found'
    return jsonify({
        'username': user.username,
        'email': user.email,
        'password': user.password,
        'id':user.id
    })
@bp.route('/about')
def about():
    return 'The about page'
 