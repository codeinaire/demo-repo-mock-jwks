import jwksClient from 'jwks-rsa'
import jwt from 'jsonwebtoken'
import util from 'util'

import { APIGatewayProxyEvent } from 'aws-lambda'

export const createCheckScopesAndResolve = ({
  jwksUri,
  audience,
  issuer,
}: {
  jwksUri: string
  audience: string
  issuer: string
}) => {
  const client = jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri,
  })

  const retrieveSigningKey = util.promisify(client.getSigningKey)

  const getSigningKey = async (keyId: string): Promise<string> => {
    const retrievedKey = await retrieveSigningKey(keyId)
    return (
      (retrievedKey as jwksClient.CertSigningKey).publicKey ||
      (retrievedKey as jwksClient.RsaSigningKey).rsaPublicKey
    )
  }

  const extractBearerToken = (event: APIGatewayProxyEvent): string => {
    const tokenString = event.headers.authorization
    if (!tokenString) {
      throw new Error(
        'Expected "event.headers.authorization" parameter to be set',
      )
    }

    const match = tokenString.match(/^Bearer (.*)$/)
    if (!match || match.length < 2) {
      throw new Error(
        `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`,
      )
    }

    return match[1]
  }

  const verifyToken = async (
    event: APIGatewayProxyEvent,
  ): Promise<IScopeAndId> => {
    const token = extractBearerToken(event)

    const decoded: IDecodedToken = jwt.decode(token, {
      complete: true,
    }) as IDecodedToken
    if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new Error('Invalid Token')
    }

    const rsaOrCertSigningKey: string = await getSigningKey(decoded.header.kid)

    const jwtOptions = {
      audience,
      issuer,
    }
    const verifiedToken: IVerifiedToken = (await jwt.verify(
      token,
      rsaOrCertSigningKey,
      jwtOptions,
    )) as IVerifiedToken

    const scopes: Array<string> = verifiedToken.scope.split(' ')

    return {
      principleId: verifiedToken.sub,
      scopes: scopes,
    }
  }

  return async (
    event: APIGatewayProxyEvent,
    expectedScopes: [string],
  ): Promise<string> => {
    const verifiedToken = await verifyToken(event)

    const scopes = verifiedToken.scopes

    if (!scopes) {
      throw new Error('No scopes supplied!')
    }

    const scopesMatch = expectedScopes.some(
      scope => scopes.indexOf(scope) !== -1,
    )
    if (scopesMatch) {
      return verifiedToken.principleId
    } else {
      throw new Error('You are not authorized!')
    }
  }
}

export interface IVerifiedToken {
  iss: string
  sub: string
  aud: [string]
  iat: number
  exp: number
  azp: string
  scope: string
}

export interface IDecodedToken {
  header: {
    typ: string
    alg: string
    kid: string
  }
  payload: {
    iss: string
    sub: string
    aud: [string]
    iat: number
    exp: number
    azp: string
    scope: string
  }
  signature: string
}

export interface IScopeAndId {
  principleId: string
  scopes: Array<string>
}

export interface IAuth {
  checkScopesAndResolve: (
    arg0: APIGatewayProxyEvent,
    arg1: [string],
  ) => Promise<string>
}
