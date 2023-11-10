const AWS = require('aws-sdk');
const crypto = require('crypto');

const secretsManager = new AWS.SecretsManager();

exports.handler = async (event, context) => {
  try {
    // Extract Authorization token from the headers
    const authorizationHeader = event.headers.Authorization || event.headers.authorization;

    // Check if the token has 'Basic' in it
    if (!authorizationHeader || !authorizationHeader.startsWith('Basic ')) {
      return generatePolicy('user', 'Deny', event.methodArn, 'The token does not have Basic in it');
    }

    // Decode the token
    const base64Credentials = authorizationHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');

    // Generate HMAC SHA256 hash of the decoded string using the secret key from environment variable
    const secretKey = process.env.LICENSEKEY;
    const generatedHash = crypto.createHmac('sha256', secretKey).update(credentials).digest('hex');

    // Extract username from the decoded string
    const username = credentials.split(':')[0];

    // Fetch secret from Secrets Manager
    const secretName = process.env.USERNAMEPATH;
    const secretValue = await getSecret(secretName);

    // Compare the fetched hash with the generated hash
    if (secretValue && secretValue.username === username && secretValue.hash === generatedHash) {
      return generatePolicy(username, 'Allow', event.methodArn);
    } else {
      return generatePolicy(username, 'Deny', event.methodArn, 'The hash does not match');
    }
  } catch (error) {
    console.error('Error:', error);
    return generatePolicy('user', 'Deny', event.methodArn, 'Internal Server Error');
  }
};

// Function to fetch secret from Secrets Manager
const getSecret = async (secretName) => {
  try {
    const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    return JSON.parse(data.SecretString);
  } catch (error) {
    console.error('Error fetching secret:', error);
    throw error;
  }
};

// Function to generate IAM policy
const generatePolicy = (principalId, effect, resource, errorMessage) => {
  const authResponse = {
    principalId: principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    },
    context: {
      errorMessage: errorMessage || 'Unauthorized',
    },
  };
  return authResponse;
};
