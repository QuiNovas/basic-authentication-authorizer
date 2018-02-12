import base64
import boto3
import hashlib
import logging.config
import os


def handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    auth_token = event['authorizationToken']
    logger.info('Client Token: {}'.format(auth_token))
    logger.info('Method ARN: {}'.format(event['methodArn']))

    if not auth_token.startswith('Basic '):
        logger.warn('Incorrect authentication - not Basic')
        raise Exception('Unauthorized')

    user_pass = base64.b64decode(auth_token[6:]).split(':', 1)
    if len(user_pass) != 2:
        logger.warn('Incomplete basic authentication - no username/password')
        raise Exception('Unauthorized')
    username = user_pass[0]
    password = user_pass[1]

    dynamodb = boto3.resource('dynamodb')

    users_table = dynamodb.Table(os.environ['USERS_TABLE_NAME'])

    user_response = users_table.get_item(
        Key={
            'Username': username
        }
    )

    if 'Item' not in user_response:
        logger.info('Username {} not in table {}'.format(username, os.environ['USERS_TABLE_NAME']))
        raise Exception('Unauthorized')

    if user_response['Item']['Password'] != hashlib.sha256(password).hexdigest():
        logger.info('Password for username {} not {}'.format(username, password))
        raise Exception('Unauthorized')

    groups_table = dynamodb.Table(os.environ['GROUPS_TABLE_NAME'])

    policy_response = groups_table.get_item(
        Key={
            'GroupId': user_response['Item']['GroupId']
        }
    )

    if 'Item' not in policy_response:
        logger.error('GroupId {} not table {}'.format(user_response['Item']['GroupId'], os.environ['GROUPS_TABLE_NAME']))
        raise Exception('Unauthorized')

    logger.info('Setting policy {} for username {}'.format(policy_response['Item']['Policy'], username))

    return {
        'principalId': username,
        'policyDocument': policy_response['Item']['Policy']
    }
