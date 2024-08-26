import os
import uuid

import boto3
import jwt
import simplejson
from boto3.dynamodb.conditions import Key
from cryptography.fernet import Fernet

dynamodb = boto3.resource('dynamodb')

request_check = {"statusCode": 400,
                 "isBase64Encoded": 'false',
                 "headers": {'Content-Type': 'application/json',
                             'Access-Control-Allow-Origin': '*',
                             'Access-Control-Allow-Headers': "Content-Type",
                             "Access-Control-Allow-Methods": "OPTIONS,POST"}
                 }


def fernet_decrypt(data: str) -> str:
    """
    Helper function to help decrypt fernet encrypted data.
    :param data: string you want to decode.
    :return: returns decoded string in utf-8 format
    """
    db_enc_key = os.environ['DB_ENC_KEY']  # Fernet Key
    f_key = Fernet(db_enc_key)
    return f_key.decrypt(data.encode('utf-8')).decode('utf-8')


def fernet_encrypt(data: str) -> str:
    """
    Helper function to help encrypt data using Fernet
    :param data: string you want to encode
    :return: encrypted data in str format.
    """
    db_enc_key = os.environ['DB_ENC_KEY']  # Fernet Key
    f_key = Fernet(db_enc_key)
    return f_key.encrypt(data.encode('utf-8')).decode('utf-8')


def encrypt_jwt(data: dict):
    """
    Helper function to create a jwt token from dict.
    :param data: dictionary of data to tokenize
    :return: token as string
    """
    jwt_key = os.environ['JWT_KEY']
    return jwt.encode(data, jwt_key, algorithm='HS256')


def decrypt_jwt(data) -> dict:
    """
    Helper function to decrypt a jwt token from string.
    :param data: raw token in str format
    :return: decrypted token in dict format
    """
    jwt_key = os.environ['JWT_KEY']
    return jwt.decode(data, jwt_key, algorithms=['HS256'])


def session_verify(event):
    """
    Takes in event header and tries to check if the session is still active.
    :param event: user provided header
    :return: updated request_check to return to user.
    """
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


def lambda_handler(event, context):
    if 'body' not in event:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Pls provide a body."})
        return request_check
    auth_header_data = event['headers']['authorization']
    provided_token = auth_header_data.split(" ")[1]
    decoded_token = decrypt_jwt(provided_token)
    event_body = event['body']
    event_body = simplejson.loads(event_body)
    try:
        ssn_check = session_verify(event)
        if ssn_check['statusCode'] != 200:
            return ssn_check
        actual_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, decoded_token['username']))
        form_type = event_body['form_type']
        forms_table = dynamodb.Table(os.environ['FORMS_FILLED'])
        form_details = forms_table.query(
            KeyConditionExpression=Key('user_id').eq(actual_user_id) & Key('form_type').eq(form_type))
        if form_details['Count'] == 0:
            request_check['statusCode'] = 400
            request_check['body'] = simplejson.dumps({"data": {}, "message": "Form not found."})
            return request_check
        decrypted_json_form_data = simplejson.loads(
            fernet_decrypt(form_details['Items'][0]['form_data']))

        form_details_response = {
            "from_data": decrypted_json_form_data,
            "created_on": str(form_details['Items'][0]['created_on'])
        }
        request_check['statusCode'] = 200
        request_check['body'] = simplejson.dumps({"data": form_details_response, "message": "Retrieved Form Data"})
        return request_check
    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check
