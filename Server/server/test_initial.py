
import pytest
from flask_jwt_extended import  decode_token
def test_user(client):
    rv = client.get("/get_user/kestel")
    print(rv.json)
    assert rv.json['username'] == 'kestel white'

def test_invalid_login(client):

    rv = client.post('/login')
    assert rv.get_json()['status'] == 'fail'
    assert rv.get_json()['message'] == 'Try again'
    assert rv.status_code == 500


def test_successful_signup(client):
# with app.test_client() as c:
    resp_signup = client.post('/register', json={
        'email': 'Tina', 'password': 'Melanka'
    })
    token = resp_signup.get_json()['access_token']
    resp_check =client.get('/who_am_i',
            headers=dict(Authorization='Bearer ' + token))
    data_json = resp_check.get_json()
    assert data_json['email'] == "Tina"