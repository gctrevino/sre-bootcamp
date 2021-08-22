# These functions need to be implemented
from datetime import datetime
import jwt
import mysql.connector
import hashlib
import os

class Token:


    def __get_user_info(self, username):
        try:
            db_url = os.getenv("DB_URL")
            db_user = os.getenv("DB_USER")
            db_password = os.getenv("DB_PASSWORD")
            db_schema = os.getenv("DB_SCHEMA")
            db_query_user = os.getenv("DB_QUERY_USER")

            user_info={}
            with mysql.connector.connect(host=db_url, user=db_user, password=db_password, db=db_schema) as conn:
                with conn.cursor() as cur:
                    query=f'{db_query_user} "{username}";'
                    cur.execute(query)
                    result_set=cur.fetchall()
                    columns=cur.description
                    for col, res in zip(columns, result_set[0]):
                        user_info[col[0]] = res
        except:
            print("There was an error validating the user.")
        finally:
            conn.close()

        return user_info


    def __validate_user_info(self, username, password):
        is_valid, role = False, ""
        try:
            user_info = self.__get_user_info(username)
            cur_pass = hashlib.sha512()
            cur_pass.update((password.encode()))
            cur_pass.update((user_info['salt']).encode())
            if cur_pass.hexdigest() == user_info['password']:
                is_valid = True
                role = user_info['role']
        except:
            print("We encountered an issue while validating the password")

        return is_valid, role


    def __jwt(self, action, data):
        try:
            key = os.getenv("KEY")
            alg = os.getenv("ALG")

            if action == 'decode':
                result_jwt = jwt.decode(data, key, algorithms=[alg])

            if action == 'encode':
                result_jwt = jwt.encode(data, key, algorithm=alg)

            return result_jwt
        except Exception as e:
            print(f'[{e}]')


    def generate_token(self, username, password):
        is_valid, role = self.__validate_user_info(username, password)
        if is_valid:
            payload = {'role':role}
            res = self.__jwt('encode', payload)
        else:
            res = f'User/pass is NOT valid'

        return res


class Restricted:


    def __jwt(self, action, data):
        try:
            key = os.getenv("KEY")
            alg = os.getenv("ALG")

            if action == 'decode':
                result_jwt = jwt.decode(data, key, algorithms=[alg])

            if action == 'encode':
                result_jwt = jwt.encode(data, key, algorithm=alg)

            return result_jwt
        except Exception as e:
            print(f'[{e}]')


    def access_data(self, authorization):
        res = ''
        try:
            decoded_jwt = self.__jwt('decode', authorization)

            role = decoded_jwt['role']

            if role in ('admin', 'editor', 'viewer'):
                res = f'You are under protected data'

            if role == 'admin':
                pass

            if role == 'editor':
                pass

            if role == 'viewer':
                pass

        except Exception as e:
            res = 'Invalid authorization'
            # print(f'[{e}]')

        return res
