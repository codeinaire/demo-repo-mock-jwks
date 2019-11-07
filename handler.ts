import { createCheckScopesAndResolve } from './auth'

//This is a singleton and will be reused on the next lambda call
const checkScopeAndResolve = createCheckScopesAndResolve({
  jwksUri: process.env.JWKS_URI as string,
  issuer: process.env.ISSUER as string,
  audience: process.env.AUDIENCE as string,
})

const handler = async (event: any) => {
  await checkScopeAndResolve(event, ['hooray'])
  // Return something useful here.
}

module.exports = { handler }
