import { APIGatewayAuthorizerResult, APIGatewayRequestAuthorizerEvent } from 'aws-lambda';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

// ─── Constants ────────────────────────────────────────────────────────────────

const userPoolId = process.env.COGNITO_USER_POOL_ID;
const clientId = process.env.COGNITO_CLIENT_ID;
if (!userPoolId) throw new Error('COGNITO_USER_POOL_ID env var is required');
if (!clientId) throw new Error('COGNITO_CLIENT_ID env var is required');

// Verifies ID tokens (not access tokens) — the ID token is what carries the
// `email` claim the app needs, and `clientId` scopes verification to this
// app's own User Pool Client.
const verifier = CognitoJwtVerifier.create({
  userPoolId,
  tokenUse: 'id',
  clientId,
});

const allowPolicy = (methodArn: string, sub: string, email: string): APIGatewayAuthorizerResult => ({
  principalId: sub,
  policyDocument: {
    Version: '2012-10-17',
    Statement: [{ Action: 'execute-api:Invoke', Effect: 'Allow', Resource: methodArn }],
  },
  context: { sub, email },
});

// ─── Entry point ──────────────────────────────────────────────────────────────

/**
 * WebSocket API Gateway has no built-in Cognito/JWT authorizer type (that's
 * REST/HTTP API only), so $connect is gated by this Lambda REQUEST
 * authorizer instead. The WS handshake can't carry custom headers, so the
 * token travels as `?token=` on the query string (see serverless.yml's
 * identitySource) — same constraint that already applies to `?nickname=`
 * on today's unauthenticated connect.
 *
 * Throwing here (rather than returning a Deny policy) is what makes API
 * Gateway reject the handshake with a clean 401 before it ever opens —
 * the client's existing `hasEverOpened` check in websocket.ts already
 * treats "closed before opening" as `connect_rejected`.
 */
export const handle = async (
  event: APIGatewayRequestAuthorizerEvent
): Promise<APIGatewayAuthorizerResult> => {
  const token = event.queryStringParameters?.['token'];
  if (!token) {
    throw new Error('Unauthorized');
  }

  try {
    const payload = await verifier.verify(token);
    const email = typeof payload['email'] === 'string' ? payload['email'] : '';
    return allowPolicy(event.methodArn, payload.sub, email);
  } catch (e) {
    console.error('[authorizer] Token verification failed:', (e as Error).message);
    throw new Error('Unauthorized');
  }
};
