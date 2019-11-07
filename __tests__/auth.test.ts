import createJWKSMock from 'mock-jwks'
import { createCheckScopesAndResolve } from '../auth'

import { APIGatewayProxyEvent } from 'aws-lambda'

const TOKEN_ISSUER = 'https://test-app.com/'

describe('Given an event with an [INCORRECT] scope', () => {
  it('Returned - You are not authorized!', async () => {
    const jwksMock = createJWKSMock(TOKEN_ISSUER)
    await jwksMock.start()

    const checkScopesAndResolve = createCheckScopesAndResolve({
      jwksUri: 'https://test-app.com/.well-known/jwks.json',
      issuer: TOKEN_ISSUER,
      audience: 'https://test-app.com/test/',
    })

    const accessToken = jwksMock.token({
      aud: ['https://test-app.com/test/'],
      iss: TOKEN_ISSUER,
      sub: 'test-user',
      scope: 'incorrect scope',
    })

    const mockedEvent = customMockedEvent({
      authorization: `Bearer ${accessToken}`,
    })

    await expect(
      checkScopesAndResolve(mockedEvent, ['incorrect scope']),
    ).rejects.toEqual(new Error('You are not authorized!'))
    await jwksMock.stop()
  })
})

function customMockedEvent(
  modificationObject: IModifiedObject,
): APIGatewayProxyEvent {
  return {
    body: '{"body": "mock body"}',
    headers: {
      mockHeaders: 'mock header',
      authorization: `${modificationObject.authorization}`,
    },
    httpMethod: 'POST',
    multiValueHeaders: {
      authorization: ['invalid token'],
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
        claims: [Object],
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
      stage: 'dev',
    },
    resource: '/nmm-app',
    stageVariables: null,
  }
}

export interface IModifiedObject {
  [name: string]: string
}
