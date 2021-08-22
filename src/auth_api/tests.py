import unittest
import requests
import json
import os
from dotenv import load_dotenv
from methods import Token, Restricted


class TestStringMethods(unittest.TestCase):


    def setUp(self):
        self.convert = Token()
        self.validate = Restricted()
        load_dotenv()


    # Modified the asserts because the encoded string is different from the one that PyJWT generates because it orders the header items in a different way
    # string provided: https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI
    # string generated: https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.BmcZ8aB5j8wLSK8CqdDwkGxZfFwM1X1gfAIN7cXOx9w
    def test_generate_token(self):
        self.assertEqual('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.BmcZ8aB5j8wLSK8CqdDwkGxZfFwM1X1gfAIN7cXOx9w', self.convert.generate_token('admin', 'secret'))
        # self.assertEqual('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI', self.convert.generate_token('admin', 'secret'))


    def test_access_data(self):
        self.assertEqual('You are under protected data', self.validate.access_data('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.BmcZ8aB5j8wLSK8CqdDwkGxZfFwM1X1gfAIN7cXOx9w'))
        # self.assertEqual('You are under protected data', self.validate.access_data('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI'))


class TestRequests(unittest.TestCase):
    def test_login_admin(self):
        url='http://127.0.0.1:8000/login'
        params={'username':'admin', 'password':'secret'}
        res = json.loads(requests.post(url, data=params).text)
        token = res['data']

        self.assertEqual(token, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.BmcZ8aB5j8wLSK8CqdDwkGxZfFwM1X1gfAIN7cXOx9w')

    def test_protected_admin(self):
        url='http://127.0.0.1:8000/login'
        params={'username':'admin', 'password':'secret'}
        res = json.loads(requests.post(url, data=params).text)
        token = res['data']

        url='http://127.0.0.1:8000/protected'
        headers = {'Accept': 'application/json', 'Authorization': token}
        res = json.loads(requests.get(url, headers=headers).text)
        status = res['data']

        self.assertEqual(status, 'You are under protected data')


    def test_protected_noadmin(self):
        url='http://127.0.0.1:8000/login'
        params={'username':'noadmin', 'password':'noPow3r'}
        res = json.loads(requests.post(url, data=params).text)
        token = res['data']

        url='http://127.0.0.1:8000/protected'
        headers = {'Accept': 'application/json', 'Authorization': token}
        res = json.loads(requests.get(url, headers=headers).text)
        status = res['data']

        self.assertEqual(status, 'You are under protected data')


    def test_protected_bob(self):
        url='http://127.0.0.1:8000/login'
        params={'username':'bob', 'password':'thisIsNotAPasswordBob'}
        res = json.loads(requests.post(url, data=params).text)
        token = res['data']

        url='http://127.0.0.1:8000/protected'
        headers = {'Accept': 'application/json', 'Authorization': token}
        res = json.loads(requests.get(url, headers=headers).text)
        status = res['data']

        self.assertEqual(status, 'You are under protected data')


if __name__ == '__main__':
    unittest.main()
