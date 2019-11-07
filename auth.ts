require('dotenv').config({ silent: true });

import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';
import util from 'util';

import { APIGatewayProxyEvent } from 'aws-lambda';

export default class Auth implements IAuth {
  constructor() {}

  private async getSigningKey(keyId: string): Promise<string> {
    console.log('testing', keyId);
    const client = jwksClient({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      jwksUri: process.env.JWKS_URI || ''
    });

    console.log('testing####', client);

    const retrieveSigningKey = util.promisify(client.getSigningKey);
    console.log('retrieveSigningKey####', retrieveSigningKey);
    const retrievedKey = await retrieveSigningKey(keyId);
    console.log('retrievedKey####', retrievedKey);
    return (retrievedKey as jwksClient.CertSigningKey).publicKey ||
    (retrievedKey as jwksClient.RsaSigningKey).rsaPublicKey;
  }

  private extractBearerToken(event: APIGatewayProxyEvent): string {
    const tokenString = event.headers.authorization;
    if (!tokenString) {
        throw new Error('Error: Expected "event.headers.authorization" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Error: Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }

    return match[1];
  }

  private async verifyToken(event: APIGatewayProxyEvent): Promise<IScopeAndId> {
    const token = this.extractBearerToken(event);

    const decoded: IDecodedToken = jwt.decode(token, { complete: true }) as IDecodedToken;
    if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new Error('Error: Invalid Token');
    }

    const rsaOrCertSigningKey: string = await this.getSigningKey(decoded.header.kid);

    const jwtOptions = {
      audience: process.env.AUDIENCE,
      issuer: process.env.TOKEN_ISSUER
    }
    const verifiedToken: IVerifiedToken = await jwt.verify(token, rsaOrCertSigningKey, jwtOptions) as IVerifiedToken;

    const scopes: Array<string> = verifiedToken.scope.split(' ');

    return {
      principleId: verifiedToken.sub,
      scopes: scopes
    }
  }

  public async checkScopesAndResolve(event: APIGatewayProxyEvent, expectedScopes: [string]): Promise<string> {
    try {
      const verifiedToken = await this.verifyToken(event);

      const scopes = verifiedToken.scopes;

      if (!scopes) {
        throw new Error('Error: No scopes supplied!');
      }

      const scopesMatch = expectedScopes.some(scope => scopes.indexOf(scope) !== -1);
      if(scopesMatch) {
        return verifiedToken.principleId;
      } else {
        throw new Error('Error: You are not authorized!');
      }
    } catch (error) {
      return error;
    }
  }
}


export interface IVerifiedToken {
  iss: string;
  sub: string;
  aud: [string];
  iat: number;
  exp: number,
  azp: string;
  scope: string;
}

export interface IDecodedToken {
  header: {
    typ: string;
    alg: string;
    kid: string;
  },
  payload: {
    iss: string;
    sub: string;
    aud: [string];
    iat: number;
    exp: number;
    azp: string;
    scope: string;
  },
  signature: string;
}

export interface IScopeAndId {
  principleId: string;
  scopes: Array<string>;
}

export interface IAuth {
  checkScopesAndResolve: (arg0: APIGatewayProxyEvent, arg1: [string]) => Promise<string>;
}