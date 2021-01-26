
from flask import render_template, url_for, flash, redirect
from flask import request
from server.models import User, Upload
from server import app,db,bcrypt
import os
import uuid

from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        allfiles = request.files.getlist('file')
        if len(allfiles) == 0:
            return "No files Upploaded"
        for file in allfiles:
            if file and allowed_file(file.filename):
                originalfilename = secure_filename(file.filename)
                server_path = os.path.join(
                    app.config['UPLOAD_FOLDER'], str(uuid.uuid4()))

                file.save(server_path)
                hashed_password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
                user_entry = User.query.filter_by(username=request.form['username']).first()
                if not user_entry:
                    user_entry=User(username=request.form['username'],password=hashed_password)
                    db.session.add(user_entry)
                    db.session.commit()
                upload_entry = Upload(original_name=originalfilename, path=server_path,user_id=user_entry.id)
                db.session.add(upload_entry)
                db.session.commit()
        return "Super"

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
