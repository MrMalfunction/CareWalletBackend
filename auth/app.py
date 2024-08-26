import os
import random
import secrets
import string
import time
import uuid

import boto3
import jwt
import simplejson
from boto3.dynamodb.conditions import Key
from cryptography.fernet import Fernet
from passlib.handlers.pbkdf2 import pbkdf2_sha256


def fernet_decrypt(data: str) -> str:
    db_enc_key = os.environ['DB_ENC_KEY']  # Fernet Key
    f_key = Fernet(str.encode(db_enc_key))
    return str(f_key.decrypt(data))


def fernet_encrypt(data: bytes):
    db_enc_key = os.environ['DB_ENC_KEY']  # Fernet Key
    f_key = Fernet(db_enc_key)
    return f_key.encrypt(data)


def encrypt_jwt(data: dict):
    jwt_key = os.environ['JWT_KEY']
    return jwt.encode(data, jwt_key, algorithm='HS256')


def decrypt_jwt(data) -> dict:
    jwt_key = os.environ['JWT_KEY']
    return jwt.decode(data, jwt_key, algorithms=['HS256'])


def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    return ''.join(random.choices(string.digits, k=length))


def send_otp_email(email, otp):
    ses_client = boto3.client('ses', region_name='us-east-1')
    """Send an OTP email using Amazon SES."""
    ses_client.send_email(
        Source=os.environ['SES_SOURCE_EMAIL'],
        Destination={'ToAddresses': [email]},
        Message={
            'Subject': {'Data': 'Your Password Reset OTP'},
            'Body': {
                'Text': {'Data': f'Your OTP for password reset is: {otp}'}
            }
        }
    )


dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table(os.environ['USER_TABLE'])
request_check = {"statusCode": 400,
                 "isBase64Encoded": 'false',
                 "headers": {'Content-Type': 'application/json',
                             'Access-Control-Allow-Origin': '*',
                             'Access-Control-Allow-Headers': "Content-Type",
                             "Access-Control-Allow-Methods": "OPTIONS,POST"}
                 }


def login(event):
    try:
        actual_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, event['username']))
        user_details = user_table.query(KeyConditionExpression=Key('user_id').eq(actual_user_id))
        if user_details['Count'] != 1:
            request_check['statusCode'] = 401
            request_check['body'] = simplejson.dumps({"data": {}, "message": "User and password do not match."})
            return request_check
        if pbkdf2_sha256.verify(event['password'], user_details['Items'][0]['password']):
            session_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))

            session_table = dynamodb.Table(os.environ['SESSION_TABLE'])

            session_created_time = int(time.time())
            session_expiry_time = session_created_time + 3600  # 1 hour expiry
            session_table.put_item(Item={
                'session_id': session_id,
                'user_id': actual_user_id,
                'created': session_created_time,
                'ttl': session_expiry_time,
            })
            jwt_token_data = {
                'session_id': session_id,
                'username': event['username'],
                # 'forms': user_forms,
                'exp': session_expiry_time
            }
            jwt_encoded = encrypt_jwt(jwt_token_data).decode("utf-8")
            request_check['statusCode'] = 200
            dump_data = simplejson.dumps({"data": jwt_encoded, "message": "Login Success"})
            request_check['body'] = dump_data
            return request_check
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Invalid username or password."})
        return request_check
    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check


def register(event):
    try:
        converted_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, event['username']))
        user_password = event['password']
        user_email = event['email']
        if user_password == "" or user_email == "" or event['username'] == "":
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Invalid username or password."})
            return request_check

        existing_user_details = user_table.query(KeyConditionExpression=Key('user_id').eq(converted_user_id))
        if existing_user_details['Count'] > 0:
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Username already exists. Pls Login"})
            return request_check
        hash_password = pbkdf2_sha256.encrypt(user_password)
        user_table.put_item(Item={'user_id': converted_user_id, 'password': hash_password, 'email': user_email})
        request_check['statusCode'] = 200
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Register Success"})
        return request_check
    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check


def session_verify(event):
    try:
        # print(event)
        auth_header_data = event['headers']['authorization']
        if auth_header_data is None:
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Session verify failed."})
            return request_check
        provided_token = auth_header_data.split(" ")[1]
        try:
            decoded_token = decrypt_jwt(provided_token)
            converted_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, decoded_token['username']))
            session_table = dynamodb.Table(os.environ['SESSION_TABLE'])
            check_query_exists = session_table.query(
                KeyConditionExpression=Key('session_id').eq(decoded_token['session_id']) & Key('user_id').eq(
                    converted_user_id))
            if check_query_exists['Count'] == 0:
                request_check['statusCode'] = 401
                request_check['body'] = simplejson.dumps({"data": {}, "message": "Session expired."})
                return request_check
            else:
                request_check['statusCode'] = 200
                request_check['body'] = simplejson.dumps({"data": {}, "message": "Session is valid."})
                return request_check
        except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError, jwt.DecodeError, jwt.InvalidTokenError) as e:
            request_check['statusCode'] = 401
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Session expired or invalid."})
            return request_check
    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": str(e)})
        return request_check


def logout(event):
    try:
        auth_header_data = event['headers'].get('authorization')
        if auth_header_data is None:
            request_check['statusCode'] = 401
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Authorization header missing."})
            return request_check

        provided_token = auth_header_data.split(" ")[1]
        try:
            decoded_token = decrypt_jwt(provided_token)
            converted_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, decoded_token['username']))
            session_table = dynamodb.Table(os.environ['SESSION_TABLE'])

            # Check if the session exists in the database
            check_query_exists = session_table.query(
                KeyConditionExpression=Key('session_id').eq(decoded_token['session_id']) & Key('user_id').eq(
                    converted_user_id)
            )
            if check_query_exists['Count'] == 0:
                request_check['statusCode'] = 401
                request_check['body'] = simplejson.dumps(
                    {"data": {}, "message": "Session already expired or does not exist."})
                return request_check
            else:
                # Invalidate the session token by deleting it from the session table
                session_table.delete_item(
                    Key={
                        'session_id': decoded_token['session_id'],
                        'user_id': converted_user_id
                    }
                )
                request_check['statusCode'] = 200
                request_check['body'] = simplejson.dumps({"data": {}, "message": "Successfully logged out."})
                return request_check

        except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError, jwt.DecodeError, jwt.InvalidTokenError) as e:
            request_check['statusCode'] = 401
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Invalid or expired session token."})
            return request_check

    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check


def reset_set_new_otp(event):
    try:
        username = event['username']
        converted_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, username))
        response = user_table.get_item(
            Key={'user_id': converted_user_id}
        )

        if 'Item' not in response:
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "User not found."})
            return request_check

        otp = generate_otp()

        # Store OTP in the database
        otp_table = dynamodb.Table(os.environ['OTP_TABLE'])
        otp_table.put_item(
            Item={
                'user_id': converted_user_id,
                'otp': otp,
                'ttl': int(time.time()) + 300  # Set TTL for OTP to 5 minutes
            }
        )

        # Send OTP email
        send_otp_email(response['Item']['email'], otp)
        request_check['statusCode'] = 200
        request_check['body'] = simplejson.dumps({"data": {}, "message": "OTP sent to your email."})
        return request_check

    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check


def reset_password(event):
    try:
        username = event['username']
        converted_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, username))
        new_password = event['new_password']
        provided_otp = event['otp']
        otp_table = dynamodb.Table(os.environ['OTP_TABLE'])
        otp_response = otp_table.get_item(
            Key={'user_id': converted_user_id}
        )
        if 'Item' not in otp_response:
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "OTP not found."})

        if int(otp_response['Item']['ttl']) < int(time.time()):
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "OTP not found."})

        stored_otp = otp_response['Item']['otp']
        if stored_otp != provided_otp:
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Incorrect OTP."})
            return request_check
        hash_password = pbkdf2_sha256.encrypt(new_password)
        user_table.update_item(
            Key={'user_id': converted_user_id},
            UpdateExpression="SET password = :new_password",
            ExpressionAttributeValues={
                ':new_password': hash_password
            }
        )
        otp_table.delete_item(
            Key={'user_id': converted_user_id}
        )
        request_check['statusCode'] = 200
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Password has been reset successfully."})
        return request_check
    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check


def lambda_handler(event, context):
    if 'body' not in event:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need a message body"})
        return request_check
    event_body = event['body']
    event_body = simplejson.loads(event_body)
    # print(event_body)

    if "type" not in event_body:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Type not provided."})
        return request_check

    elif event_body['type'] == "login":
        return login(event_body)

    elif event_body['type'] == "register":
        return register(event_body)

    elif event_body['type'] == "session_verify":
        return session_verify(event)

    elif event_body['type'] == "logout":
        return logout(event)

    elif event_body['type'] == "reset":
        return reset_set_new_otp(event_body)

    elif event_body['type'] == "reset_password":
        return reset_password(event_body)

    else:
        request_check['statusCode'] = 400
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Invalid request type."})
        return request_check
