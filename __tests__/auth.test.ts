import createJWKSMock from 'mock-jwks';
import Auth from '../auth';

import { APIGatewayProxyEvent } from 'aws-lambda';

describe('Given an event with an [INCORRECT] scope', () => {
  it('Returned - You are not authorized!', async () => {
    // const jwksMock = await createJwksContext();
    process.env.JWKS_URI = 'https://test-app.com/.well-known/jwks.json';
    process.env.TOKEN_ISSUER = 'https://test-app.com/';
    process.env.AUDIENCE = 'https://test-app.com/test/';
    const jwksMock = createJWKSMock('https://test-app.com/');
    await jwksMock.start();
    const accessToken = jwksMock.token({
      aud: [
        'https://test-app.com/test/'
      ],
      iss: 'https://test-app.com/',
      sub: 'test-user',
      scope: 'incorrect scope'
    })
    console.log('accessToken', accessToken);


    const mockedEvent = customMockedEvent({
      authorization: `Bearer ${accessToken}`
    });

    const authInstance = new Auth();

    expect(authInstance.checkScopesAndResolve(mockedEvent, ['incorrect scope'])).resolves.toThrow('Error: You are not authorized!');
    await jwksMock.stop();
  })
})


function customMockedEvent(modificationObject: IModifiedObject): APIGatewayProxyEvent {
  return {
    body: '{"body": "mock body"}',
    headers: {
      mockHeaders: 'mock header',
      authorization: `${modificationObject.authorization}`,
    },
    httpMethod: 'POST',
    multiValueHeaders: {
      authorization: [
        'invalid token'
      ]
    },
    isBase64Encoded: false,
    multiValueQueryStringParameters: null,
    path: '/nmm-app',
    pathParameters: null,
    queryStringParameters: null,
    requestContext: {
      accountId: 'offlineContext_accountId',
      apiId: 'offlineContext_apiId',
      authorizer: {
        principalId: 'offlineContext_authorizer_principalId',
        claims: [Object]
      },
      httpMethod: 'POST',
      identity: {
        accessKey: 'test string',
        accountId: 'test string',
        apiKey: 'test string',
        apiKeyId: 'test string',
        caller: 'test string',
        cognitoAuthenticationProvider: 'test string',
        cognitoAuthenticationType: 'test string',
        cognitoIdentityId: 'test string',
        cognitoIdentityPoolId: 'test string',
        sourceIp: 'test string',
        user: 'test string',
        userAgent: 'test string',
        userArn: 'test string',
      },
      path: 'test path',
      requestId: 'offlineContext_requestId_ck1lg5mc8000j3aeh0hjq82sm',
      requestTimeEpoch: 1570756990015,
      resourceId: 'offlineContext_resourceId',
      resourcePath: '/nmm-app',
      stage: 'dev'
    },
    resource: '/nmm-app',
    stageVariables: null
  }
}

export interface IModifiedObject {
  [name: string]: string
}