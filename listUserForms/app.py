import json
import os
import uuid

import boto3
import jwt
import simplejson
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')

request_check = {"statusCode": 400,
                 "isBase64Encoded": 'false',
                 "headers": {'Content-Type': 'application/json',
                             'Access-Control-Allow-Origin': '*',
                             'Access-Control-Allow-Headers': "Content-Type",
                             "Access-Control-Allow-Methods": "OPTIONS,POST"}
                 }


def encrypt_jwt(data: dict):
    jwt_key = os.environ['JWT_KEY']
    return jwt.encode(data, jwt_key, algorithm='HS256')


def decrypt_jwt(data) -> dict:
    jwt_key = os.environ['JWT_KEY']
    return jwt.decode(data, jwt_key, algorithms=['HS256'])


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


def lambda_handler(event, context):
    if 'body' not in event:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Pls provide a body."})
        return request_check
    event_body = event['body']
    event_body = json.loads(event_body)
    try:
        ssn_check = session_verify(event)
        if ssn_check['statusCode'] != 200:
            return ssn_check
        actual_user_id = str(uuid.uuid5(uuid.NAMESPACE_OID, event_body['username']))
        forms_table = dynamodb.Table(os.environ['FORMS_FILLED'])
        query_params = {
            'KeyConditionExpression': 'user_id = :user_id',
            'ExpressionAttributeValues': {
                ':user_id': {'S': actual_user_id}
            },
            'ProjectionExpression': 'user_id, form_type, created_on'  # Excluding 'form_data'
        }
        response = forms_table.query(ProjectionExpression="form_type, created_on",
                                     KeyConditionExpression=Key('user_id').eq(actual_user_id))
        all_forms = []
        while True:
            # Extend the all_forms list with the current batch of items
            all_forms.extend(response['Items'])

            # Check if there is more data to retrieve
            if 'LastEvaluatedKey' in response:
                # If there is more data, update the query_params to continue from where it left off
                response = forms_table.query(ProjectionExpression="form_type, created_on",
                                             KeyConditionExpression=Key('user_id').eq(actual_user_id),
                                             ExclusiveStartKey=response['LastEvaluatedKey'])
            else:
                # If no more data, break the loop
                break
        request_check['statusCode'] = 200
        request_check['body'] = simplejson.dumps({"data": all_forms, "message": "All forms returned."})
        return request_check

    except KeyError as e:
        request_check['body'] = simplejson.dumps({"data": {}, "message": "Need this data " + str(e)})
        return request_check
