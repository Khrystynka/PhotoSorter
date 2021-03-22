from flask import json
import pytest
from werkzeug.datastructures import FileStorage
import os
from server.models import Upload, User, Tag



def test_user(client):
    rv = client.get("/get_user/tina")
    print(rv.json)
    assert rv.json['username'] == 'tinochka'

def test_invalid_login(client):

    rv = client.post('/login')
    assert rv.get_json()['status'] == 'fail'
    assert rv.get_json()['message'] == 'Try again'
    assert rv.status_code == 500


def test_successful_signup(client):
# with app.test_client() as c:
    resp_signup = client.post('/register', json={
        'email': 'kestel', 'password': 'white'
        })
    token = resp_signup.get_json()['access_token']
    resp_check =client.get('/who_am_i',
            headers=dict(Authorization='Bearer ' + token))
    data_json = resp_check.get_json()
    assert data_json['email'] == "kestel"
    assert data_json["status"] == 'success'
    assert resp_check.status_code == 200

def test_valid_login(client):
    resp_signup = client.post('/register', json={
        'email': 'torry', 'password': 'bella'
    })
    # token = resp_signup.get_json()['access_token']
    rv1 = client.post('/login',json={
        'email': 'torry', 'password': 'bella'
    })
    rv2 = client.post('/login',json={
        'email': 'kestel', 'password': 'white'
    })
    rv3 = client.post('/login',json={
        'email': 'tina', 'password': 'melanka'
    })
    assert rv3.get_json()['status'] == 'success'
    assert rv1.get_json()['status'] == 'success'
    assert rv2.get_json()['status'] == 'fail'
    # assert rv.get_json()['message'] == 'Try again'
    # assert rv.status_code == 500
def test_valid_upload(client):
    resp_signup = client.post('/register', json={
        'email': 'torry', 'password': 'bella'
    })
    token = resp_signup.get_json()['access_token']
  
    rv1 = client.post('/login',json={
        'email': 'torry', 'password': 'bella'
    })
    my_file = os.path.join("/Users/khrystyna/Desktop/PhotoProject/Server/server/tests/assets/deck.jpg")

    my_file = FileStorage(
        stream=open(my_file, "rb"),
        filename="deck.jpg",
        content_type="image/jpg",
    ),

    rv = client.post("/upload", headers=dict(Authorization='Bearer ' + token),
    data={
        "file": my_file,
        'tags':"friends,family"
    },
    content_type="multipart/form-data"
    )
    print(rv.get_json())
        
    user = User.query.filter_by(email='torry').first()
    uploads = [upload.original_name for upload in user.uploads]
    upload = Upload.query.filter_by(id=rv.get_json()['upload_id']).first()
    tags = [tag.name for tag in upload.tags]
    print(tags)
    assert 'family' in tags
    assert 'deck.jpg' in uploads
    assert 'deck.jpg' == upload.original_name
    assert rv.get_json()['status'] == 'success'
    assert rv.get_json()['upload_id']
    # assert rv1.get_json()['status'] == 'success'
    # assert rv2.get_json()['status'] == 'success'

def test_user_tags(client):
    
    rv = client.post('/login',json={
        'email': 'tina', 'password': 'melanka'
    })
    token = rv.get_json()['access_token']

    my_file = os.path.join("/Users/khrystyna/Desktop/PhotoProject/Server/server/tests/assets/friends.jpg")

    my_file = FileStorage(
        stream=open(my_file, "rb"),
        filename="friends.jpg",
        content_type="image/jpg",
    ),

    rv = client.post("/upload", headers=dict(Authorization='Bearer ' + token),
    data={
        "file": my_file,
        'tags':"friends,tina,polina,wooden castle park"
    },
    content_type="multipart/form-data"
    )
    rv_upload_id = rv.get_json()['upload_id']
    rv_get_tags= client.get("/get_tags", headers=dict(Authorization='Bearer ' + token))
    rv_tags = rv_get_tags.get_json()
    print(rv_tags)
    upload = Upload.query.filter_by(id=rv_upload_id).first()
    tags = [tag.name for tag in upload.tags]
    assert 'friends' in tags
    assert 'friends.jpg' == upload.original_name
    assert sorted(rv_tags)==sorted(tags)
    # assert rv1.get_json()['status'] == 'success'
    # assert rv2.get_json()['status'] == 'success'
