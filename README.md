# basic-authentication-authorizer
Uses HTTP Basic Authentication against two dynamodb tables to authorize API Gateway users.

The first table is the "users" table. This table contains the _Username_, a SHA256 hashed _Password_, and a _GroupId_.

If the user is found in the "users" table and the hash of the password matches, then the group IS is looked up in the "groups" table.

The "groups" table contains the _GroupId_ and a _Policy_ JSON document representing the IAM policy document for that user. It is this document that is returned to API Gateway for further processing.

This function supports the following environment variables:
1. **USERS_TABLE_NAME** - The DynamoDB table that contains the user data, as listed above.
2. **GROUPS_TABLE_NAME** - The DynamoDB table that contains the groups data, as listed above.

Easy implementation of this function via Terraform may be found in the following module: 

https://github.com/QuiNovas/terraform-modules/tree/master/aws/basic-authentication-authenticator