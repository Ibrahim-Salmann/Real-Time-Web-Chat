import {
  APIGatewayProxyEventQueryStringParameters,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import AWS, { AWSError } from 'aws-sdk';
import { v4 } from 'uuid';
import { getUploadUrl as getS3UploadUrl, getMediaUrl as getS3MediaUrl, deleteMedia } from './s3';

// ─── Types ────────────────────────────────────────────────────────────────────

type APIGatewayRouteKey =
  | '$connect'
  | '$disconnect'
  | '$default'
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'
  | 'getSession'
  | 'updateNickname'
  | 'typing'
  | 'markRead'
  | 'getUploadUrl'
  | 'getMediaUrl'
  | 'deleteMessage';

type ClientMessageAction =
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'
  | 'getSession'
  | 'updateNickname'
  | 'typing'
  | 'markRead'
  | 'getUploadUrl'
  | 'getMediaUrl'
  | 'deleteMessage';

/**
 * Message Echo Strategy: Option B — sender does NOT receive a message echo.
 * The frontend applies optimistic updates; echoing would cause duplicate rendering.
 * The sender receives only a `message_status_update` event containing the messageId and status.
 */

type MessageStatus = 'sent' | 'delivered' | 'read';

type Client = {
  connectionId: string;
  nickname: string;
  sub: string;
  ttl?: number;
};

type User = {
  sub: string;
  nickname: string;
  email: string;
};

/** Verified claims forwarded by `wsAuthorizer` via the REQUEST authorizer's `context`. */
type AuthContext = {
  sub: string;
  email: string;
};

type ClientMessage = {
  action: ClientMessageAction;
  data?: unknown;
};

type AttachmentMeta = {
  key: string;
  contentType: string;
  fileSize: number;
  width?: number;
  height?: number;
  duration?: number;
  fileName?: string;
};

type SendMessageBody = {
  recipientNickname: string;
  message: string;
  attachment?: AttachmentMeta;
};

type GetUploadUrlBody = {
  requestId: string;
  contentType: string;
  fileSize: number;
};

type GetMediaUrlBody = {
  requestId: string;
  key: string;
};

type DeleteMessageBody = {
  chatKey: string;
  messageId: string;
  createdAt: number;
};

type GetMessagesBody = {
  targetNickname: string;
  startKey?: AWS.DynamoDB.DocumentClient.Key;
  limit: number;
};

type TypingBody = {
  recipient: string;
  isTyping: boolean;
};

type MarkReadBody = {
  chatKey: string;
};

type UpdateNicknameBody = {
  nickname: string;
};

// ─── Constants ────────────────────────────────────────────────────────────────

const CLIENTS_TABLE = 'Clients';
const MESSAGES_TABLE = 'Messages';
const USERS_TABLE = 'Users';
const MAX_MESSAGE_LENGTH = 2000;
const NICKNAME_RE = /^[a-zA-Z0-9_-]{1,32}$/;
const CHAT_KEY_RE = /^[a-zA-Z0-9_-]{1,32}#[a-zA-Z0-9_-]{1,32}$/;
const CLIENT_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024; // 10MB — matches the mobile client's config.limits.maxFileSize

// Extension used for the generated S3 key — also doubles as the content-type
// allowlist (anything not in this map is rejected in handleGetUploadUrl).
const EXTENSION_BY_CONTENT_TYPE: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/heic': 'heic',
  'image/gif': 'gif',
  'audio/m4a': 'm4a',
  'audio/x-m4a': 'm4a',
  'audio/mp4': 'm4a',
  'audio/aac': 'aac',
  'audio/mpeg': 'mp3',
  'audio/wav': 'wav',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
  'application/msword': 'doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
  'application/zip': 'zip',
  'application/json': 'json',
  'application/octet-stream': 'bin',
};

// ─── AWS Clients ──────────────────────────────────────────────────────────────

const docClient = new AWS.DynamoDB.DocumentClient({
  region: process.env.AWS_REGION || 'us-east-1',
});

const apiGatewayEndpoint = process.env.WSSAPIGATEWAYENDPOINT;
if (!apiGatewayEndpoint) throw new Error('WSSAPIGATEWAYENDPOINT env var is required');

const apigw = new AWS.ApiGatewayManagementApi({ endpoint: apiGatewayEndpoint });

// ─── Error class ──────────────────────────────────────────────────────────────

class HandlerError extends Error {}

// ─── Logging util ─────────────────────────────────────────────────────────────

/** Strip CR/LF from any user-controlled string before it touches a log line (CWE-117). */
const sanitizeLog = (v: string) => v.replace(/[\r\n\t]/g, '_');

// ─── Entry point ──────────────────────────────────────────────────────────────

export const handle = async (
  event: APIGatewayProxyEvent,
  _context: Context
): Promise<APIGatewayProxyResult> => {
  const routeKey = event.requestContext.routeKey as APIGatewayRouteKey;
  const connectionId = (event.requestContext.connectionId ?? '').replace(/[\r\n]/g, '');

  try {
    switch (routeKey) {
      case '$connect': {
        // Populated by `wsAuthorizer`'s REQUEST authorizer context (see
        // serverless.yml's `$connect` event) — API Gateway already rejected
        // the handshake with a 401 before this code runs if verification
        // failed, so `sub`/`email` are guaranteed present here.
        const authorizer = event.requestContext.authorizer as unknown as AuthContext;
        return await handleConnect(connectionId, event.queryStringParameters, authorizer);
      }
      case '$disconnect':
        return await handleDisconnect(connectionId);
      case '$default':
      case 'sendMessage':
      case 'getMessages':
      case 'getClients':
      case 'getSession':
      case 'updateNickname':
      case 'typing':
      case 'markRead':
      case 'getUploadUrl':
      case 'getMediaUrl':
      case 'deleteMessage':
        return await handleDefaultRoute(connectionId, event.body);
      default:
        return { statusCode: 400, body: JSON.stringify({ message: 'Unknown route' }) };
    }
  } catch (err) {
    if (err instanceof HandlerError) {
      return { statusCode: 400, body: JSON.stringify({ message: err.message }) };
    }
    console.error('[handler] Unhandled error:', err);
    return { statusCode: 500, body: JSON.stringify({ message: 'Internal server error' }) };
  }
};

// ─── Default route dispatcher ─────────────────────────────────────────────────

const handleDefaultRoute = async (
  connectionId: string,
  bodyString: string | null
): Promise<APIGatewayProxyResult> => {
  let msg: ClientMessage;

  try {
    const parsed = JSON.parse(bodyString || '{}') as Record<string, unknown>;
    const valid: ClientMessageAction[] = ['sendMessage', 'getMessages', 'getClients', 'getSession', 'updateNickname', 'typing', 'markRead', 'getUploadUrl', 'getMediaUrl', 'deleteMessage'];
    if (typeof parsed.action !== 'string' || !valid.includes(parsed.action as ClientMessageAction)) {
      throw new HandlerError(parsed.action ? `Unknown action: ${parsed.action}` : 'Missing "action" field');
    }
    msg = parsed as unknown as ClientMessage;
  } catch (e) {
    if (e instanceof SyntaxError) throw new HandlerError('Invalid JSON body');
    throw e;
  }

  // getClients does not need the caller's identity
  const client = msg.action !== 'getClients' ? await getClient(connectionId) : undefined;

  switch (msg.action) {
    case 'sendMessage':
      return handleSendMessage(client!, msg.data);
    case 'getMessages':
      return handleGetMessages(client!, msg.data);
    case 'getClients':
      return handleGetClients(connectionId);
    case 'getSession':
      return handleGetSession(client!);
    case 'updateNickname':
      return handleUpdateNickname(client!, msg.data);
    case 'typing':
      return handleTyping(client!, msg.data);
    case 'markRead':
      return handleMarkRead(client!, msg.data);
    case 'getUploadUrl':
      return handleGetUploadUrl(client!, msg.data);
    case 'getMediaUrl':
      return handleGetMediaUrl(client!, msg.data);
    case 'deleteMessage':
      return handleDeleteMessage(client!, msg.data);
    default:
      throw new HandlerError('Unhandled action');
  }
};

// ─── $connect ─────────────────────────────────────────────────────────────────

const handleConnect = async (
  connectionId: string,
  queryParams: APIGatewayProxyEventQueryStringParameters | null,
  authorizer: AuthContext
): Promise<APIGatewayProxyResult> => {
  const { sub, email } = authorizer;

  // ── Resolve identity: existing user, or first-login nickname claim ───────
  // Nickname is bound permanently to `sub` at first connect — from here on
  // it's a display name attached to a real authenticated user, not the
  // identity itself (the client-supplied nickname is only consulted the
  // very first time a given `sub` ever connects).
  const existingUser = await getUserBySub(sub);
  let nickname: string;

  if (existingUser) {
    nickname = existingUser.nickname;
  } else {
    const requestedNickname = queryParams?.nickname;
    if (!requestedNickname || !NICKNAME_RE.test(requestedNickname)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'nickname must be 1–32 alphanumeric / _ / - characters' }),
      };
    }

    const nicknameTaken = await getUserByNickname(requestedNickname);
    if (nicknameTaken) {
      return {
        statusCode: 409,
        body: JSON.stringify({ message: `Nickname '${sanitizeLog(requestedNickname)}' is already taken` }),
      };
    }

    try {
      // ConditionExpression only guards this `sub` racing itself (two
      // concurrent first connects before either commits) — it does not make
      // nickname uniqueness atomic against a *different* sub claiming the
      // same nickname at the same time. Same class of best-effort race the
      // stale-session eviction below already accepts for connection takeover.
      await docClient.put({
        TableName: USERS_TABLE,
        Item: { sub, nickname: requestedNickname, email },
        ConditionExpression: 'attribute_not_exists(#sub)',
        ExpressionAttributeNames: { '#sub': 'sub' },
      }).promise();
      nickname = requestedNickname;
    } catch (e) {
      if ((e as AWSError).code !== 'ConditionalCheckFailedException') throw e;
      // Lost the race to a concurrent connect from the same user — use
      // whichever nickname that other attempt actually committed.
      const raced = await getUserBySub(sub);
      if (!raced) throw e;
      nickname = raced.nickname;
    }
  }

  // ── Stale-session eviction ────────────────────────────────────────────────
  // If a previous record exists for this nickname, probe the old connection.
  // If the old connection is dead (410) it gets deleted by postToConnection and
  // we allow the new connection to proceed. If it is still alive, reject with 409.
  const existingConnectionId = await getConnectionIdByNickname(nickname);
  if (existingConnectionId) {
    const alive = await probeConnection(existingConnectionId);
    if (alive) {
      return {
        statusCode: 409,
        body: JSON.stringify({ message: `Nickname '${sanitizeLog(nickname)}' is already connected` }),
      };
    }
    // The stale record was already deleted inside probeConnection → fall through
  }

  await docClient.put({
    TableName: CLIENTS_TABLE,
    Item: {
      connectionId,
      nickname,
      sub,
      ttl: Math.floor(Date.now() / 1000) + CLIENT_TTL_SECONDS,
    },
  }).promise();

  console.info(`[connect] nickname=${sanitizeLog(nickname)} connectionId=${sanitizeLog(connectionId)}`);

  // Deliberately do NOT postToConnection(connectionId, ...) here, to this
  // same connectionId, from within this same $connect invocation: API
  // Gateway's Management API returns 410 Gone for any postToConnection call
  // made before $connect itself has returned, since the connection isn't
  // "live" yet from its perspective. postToConnection treats a 410 as proof
  // of a truly-dead session and deletes the Clients row for it — which,
  // called on ourselves here, deleted the row we *just* inserted above,
  // moments after every single connect. (Confirmed via CloudWatch: paired
  // "[ws] Stale connection evicted" warnings citing this exact connectionId
  // on every connect.) The client fetches its own `session`/`clients` state
  // via `getSession`/`getClients` right after it sees `connected` instead
  // (see useWebSocket.ts) — those run in a later, separate invocation once
  // $connect has fully returned, so the connection is live by then.
  await notifyClientChange(connectionId);

  return { statusCode: 200, body: JSON.stringify({ message: 'Connected' }) };
};

// ─── $disconnect ──────────────────────────────────────────────────────────────

const handleDisconnect = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  const client = await getClient(connectionId).catch(() => null);

  if (client) {
    await docClient.delete({ TableName: CLIENTS_TABLE, Key: { connectionId } }).promise();
    console.info(`[disconnect] nickname=${sanitizeLog(client.nickname)} connectionId=${sanitizeLog(connectionId)}`);
    await notifyClientChange(connectionId);
  }

  return { statusCode: 200, body: JSON.stringify({ message: 'Disconnected' }) };
};

// ─── sendMessage ──────────────────────────────────────────────────────────────

const handleSendMessage = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseSendMessageBody(data);

  if (body.recipientNickname === client.nickname) {
    throw new HandlerError('Cannot send a message to yourself');
  }

  const sanitized = sanitizeMessage(body.message);
  const chatKey = getChatKey(client.nickname, body.recipientNickname);
  const messageId = v4();
  const createdAt = Date.now();
  let status: MessageStatus = 'sent';

  // ── Deliver to recipient if online ────────────────────────────────────────
  const recipientConnectionId = await getConnectionIdByNickname(body.recipientNickname);
  if (recipientConnectionId) {
    const delivered = await postToConnection(
      recipientConnectionId,
      JSON.stringify({
        type: 'message',
        payload: {
          messageId,
          chatKey,
          sender: client.nickname,
          message: sanitized,
          createdAt,
          status: 'delivered',
          ...(body.attachment ? { attachment: body.attachment } : {}),
        },
      })
    );
    if (delivered) status = 'delivered';
  }

  // ── Persist with resolved status ──────────────────────────────────────────
  await docClient.put({
    TableName: MESSAGES_TABLE,
    Item: {
      messageId,
      nicknameToNickname: chatKey,
      message: sanitized,
      sender: client.nickname,
      createdAt,
      status,
      ...(body.attachment ? { attachment: body.attachment } : {}),
    },
  }).promise();

  // ── Notify sender of status only (no echo) ────────────────────────────────
  // Isolated: a failure here must not surface as a 500 — the message was already delivered.
  await postToConnection(
    client.connectionId,
    JSON.stringify({ type: 'message_status_update', payload: { messageId, chatKey, status } })
  ).catch(e => console.error('[sendMessage] Failed to send status update to sender:', (e as Error).message));

  return { statusCode: 200, body: '' };
};

// ─── getMessages ──────────────────────────────────────────────────────────────

const handleGetMessages = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseGetMessageBody(data);
  const chatKey = getChatKey(client.nickname, body.targetNickname);

  const queryInput: AWS.DynamoDB.DocumentClient.QueryInput = {
    TableName: MESSAGES_TABLE,
    IndexName: 'NicknameToNicknameIndex',
    KeyConditionExpression: '#ntn = :ntn',
    ExpressionAttributeNames: { '#ntn': 'nicknameToNickname' },
    ExpressionAttributeValues: { ':ntn': chatKey },
    Limit: body.limit,
    ScanIndexForward: false,
  };
  if (body.startKey) queryInput.ExclusiveStartKey = body.startKey;

  const output = await docClient.query(queryInput).promise();

  await postToConnection(
    client.connectionId,
    JSON.stringify({
      type: 'messages',
      payload: { chatKey, messages: output.Items ?? [], lastEvaluatedKey: output.LastEvaluatedKey },
    })
  );

  return { statusCode: 200, body: '' };
};

// ─── getClients ───────────────────────────────────────────────────────────────

const handleGetClients = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  const allClients = await getAllClients();
  await postToConnection(
    connectionId,
    JSON.stringify({ type: 'clients', payload: allClients.map(c => ({ nickname: c.nickname })) })
  );
  return { statusCode: 200, body: '' };
};

// ─── getSession ───────────────────────────────────────────────────────────────

/**
 * Client-requested equivalent of the old connect-time `session` push (see
 * the note in `handleConnect`). Called right after the client sees its own
 * `connected` event — by then $connect has fully returned, so this
 * postToConnection targets a connection API Gateway considers live.
 */
const handleGetSession = async (client: Client): Promise<APIGatewayProxyResult> => {
  await postToConnection(
    client.connectionId,
    JSON.stringify({ type: 'session', payload: { nickname: client.nickname, sub: client.sub } })
  );
  return { statusCode: 200, body: '' };
};

// ─── updateNickname ───────────────────────────────────────────────────────────

/**
 * Renames the caller's display name. Note this does NOT migrate chat
 * history: `Messages`/`Clients` are keyed by the literal nickname string
 * (see `NicknameToNicknameIndex`), so existing threads under the old name
 * stay put under that name — a deliberate, accepted trade-off for shipping
 * this quickly rather than re-keying everything off `sub`.
 *
 * Unlike most other actions here, failures are reported back to the caller
 * explicitly via `action_error` instead of throwing `HandlerError` — a
 * thrown HandlerError's `{statusCode:400,...}` return value is never
 * delivered to a WS client on a non-$connect route (API Gateway doesn't
 * forward it), so silently throwing here would leave the UI hanging with
 * no way to know the rename failed.
 */
const handleUpdateNickname = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const { nickname: requested } = parseUpdateNicknameBody(data);

  const respondError = (message: string) =>
    postToConnection(
      client.connectionId,
      JSON.stringify({ type: 'action_error', payload: { action: 'updateNickname', message } })
    );

  if (!NICKNAME_RE.test(requested)) {
    await respondError('Letters, numbers, underscores, and hyphens only — no spaces.');
    return { statusCode: 200, body: '' };
  }

  if (requested === client.nickname) {
    // No-op rename — just re-confirm the (unchanged) session, no writes needed.
    await postToConnection(
      client.connectionId,
      JSON.stringify({ type: 'session', payload: { nickname: client.nickname, sub: client.sub } })
    );
    return { statusCode: 200, body: '' };
  }

  const existing = await getUserByNickname(requested);
  if (existing && existing.sub !== client.sub) {
    await respondError(`'${sanitizeLog(requested)}' is already taken.`);
    return { statusCode: 200, body: '' };
  }

  await docClient.update({
    TableName: USERS_TABLE,
    Key: { sub: client.sub },
    UpdateExpression: 'SET nickname = :n',
    ExpressionAttributeValues: { ':n': requested },
  }).promise();

  await docClient.update({
    TableName: CLIENTS_TABLE,
    Key: { connectionId: client.connectionId },
    UpdateExpression: 'SET nickname = :n',
    ExpressionAttributeValues: { ':n': requested },
  }).promise();

  console.info(`[updateNickname] sub=${sanitizeLog(client.sub)} ${sanitizeLog(client.nickname)} -> ${sanitizeLog(requested)}`);

  await postToConnection(
    client.connectionId,
    JSON.stringify({ type: 'session', payload: { nickname: requested, sub: client.sub } })
  );
  await notifyClientChange(client.connectionId);

  return { statusCode: 200, body: '' };
};

// ─── typing ───────────────────────────────────────────────────────────────────

const handleTyping = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseTypingBody(data);

  // Never persisted — forward only to the target recipient.
  // postToConnection handles stale connections silently.
  const recipientConnectionId = await getConnectionIdByNickname(body.recipient);
  if (recipientConnectionId) {
    await postToConnection(
      recipientConnectionId,
      JSON.stringify({ type: 'typing', payload: { sender: client.nickname, isTyping: body.isTyping } })
    ).catch(() => {
      // Stale recipient: postToConnection already cleaned up the record.
      // Safe to swallow — typing events are best-effort.
    });
  }

  return { statusCode: 200, body: '' };
};

// ─── markRead ─────────────────────────────────────────────────────────────────

/**
 * Called by the recipient when they open a conversation.
 * Marks all `delivered` messages (sent by the other party) as `read` and
 * notifies the original sender via `message_status_update`.
 *
 * Correctness guarantees:
 *  - chatKey is re-sorted server-side to reject unsorted or malformed keys.
 *  - UpdateItem uses ConditionExpression `status = delivered` for idempotency —
 *    already-`read` messages are skipped with zero WCU charge on the no-op path.
 *  - All DynamoDB pages are consumed so no messages are silently skipped.
 */
const handleMarkRead = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseMarkReadBody(data);

  // Re-derive the canonical key from the two participants; this also validates
  // that the caller is actually a participant.
  const parts = body.chatKey.split('#');
  if (parts.length !== 2) throw new HandlerError('chatKey must be in "A#B" format');
  const [partA, partB] = parts as [string, string];
  if (!NICKNAME_RE.test(partA) || !NICKNAME_RE.test(partB)) {
    throw new HandlerError('chatKey contains invalid nickname segments');
  }

  const canonicalKey = getChatKey(partA, partB);
  if (!parts.includes(client.nickname)) {
    throw new HandlerError('You are not a participant of this conversation');
  }

  const otherNickname = partA === client.nickname ? partB : partA;

  // ── Paginate through ALL delivered messages in this conversation ──────────
  const toUpdate: Array<{ messageId: string; createdAt: number }> = [];
  let lastKey: AWS.DynamoDB.DocumentClient.Key | undefined;

  do {
    const page = await docClient.query({
      TableName: MESSAGES_TABLE,
      IndexName: 'NicknameToNicknameIndex',
      KeyConditionExpression: '#ntn = :ntn',
      FilterExpression: '#status = :delivered AND #sender = :other',
      ExpressionAttributeNames: {
        '#ntn': 'nicknameToNickname',
        '#status': 'status',
        '#sender': 'sender',
      },
      ExpressionAttributeValues: {
        ':ntn': canonicalKey,
        ':delivered': 'delivered' as MessageStatus,
        ':other': otherNickname,
      },
      ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
    }).promise();

    for (const item of page.Items ?? []) {
      toUpdate.push({ messageId: item['messageId'] as string, createdAt: item['createdAt'] as number });
    }
    lastKey = page.LastEvaluatedKey as AWS.DynamoDB.DocumentClient.Key | undefined;
  } while (lastKey);

  if (toUpdate.length === 0) return { statusCode: 200, body: '' };

  // ── Update with idempotency guard ─────────────────────────────────────────
  const updatedIds: string[] = [];

  await Promise.all(
    toUpdate.map(async ({ messageId, createdAt }) => {
      try {
        await docClient.update({
          TableName: MESSAGES_TABLE,
          Key: { messageId, createdAt },
          UpdateExpression: 'SET #status = :read',
          ConditionExpression: '#status = :delivered',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':read': 'read' as MessageStatus,
            ':delivered': 'delivered' as MessageStatus,
          },
        }).promise();
        updatedIds.push(messageId);
      } catch (e) {
        // ConditionalCheckFailedException means status was already updated — safe to ignore.
        if ((e as AWSError).code !== 'ConditionalCheckFailedException') {
          console.error('[markRead] UpdateItem failed for messageId:', sanitizeLog(messageId), e);
        }
      }
    })
  );

  if (updatedIds.length === 0) return { statusCode: 200, body: '' };

  // ── Notify the sender ─────────────────────────────────────────────────────
  const senderConnectionId = await getConnectionIdByNickname(otherNickname);
  if (senderConnectionId) {
    await postToConnection(
      senderConnectionId,
      JSON.stringify({
        type: 'message_status_update',
        payload: { chatKey: canonicalKey, messageIds: updatedIds, status: 'read' as MessageStatus },
      })
    ).catch(e => console.error('[markRead] Failed to notify sender:', (e as Error).message));
  }

  return { statusCode: 200, body: '' };
};

// ─── getUploadUrl ─────────────────────────────────────────────────────────────

/**
 * Presigned S3 PUT for a client to upload an image/audio/file attachment
 * directly — the bytes never pass through this Lambda, avoiding the WS
 * frame's implicit size limits. `requestId` round-trips a client-generated
 * id so the response can be matched to the right in-flight request; nothing
 * else in this protocol needs request/response correlation today.
 */
const handleGetUploadUrl = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseGetUploadUrlBody(data);
  const ext = EXTENSION_BY_CONTENT_TYPE[body.contentType];

  if (!ext) {
    throw new HandlerError(`Unsupported contentType: ${body.contentType}`);
  }
  if (body.fileSize > MAX_ATTACHMENT_BYTES) {
    throw new HandlerError(`fileSize exceeds ${MAX_ATTACHMENT_BYTES} bytes`);
  }

  const key = `chat-media/${client.sub}/${v4()}.${ext}`;
  const uploadUrl = await getS3UploadUrl(key, body.contentType);

  await postToConnection(
    client.connectionId,
    JSON.stringify({ type: 'uploadUrl', payload: { requestId: body.requestId, uploadUrl, key } })
  );

  return { statusCode: 200, body: '' };
};

// ─── getMediaUrl ──────────────────────────────────────────────────────────────

/**
 * Presigned S3 GET for viewing/downloading a previously-uploaded attachment.
 * MVP trusts key-opacity (UUID-named keys under a per-sub prefix aren't
 * enumerable) rather than cross-checking the requester is a real
 * participant in the message that references this key — accepted gap, not
 * a hardening pass for this iteration.
 */
const handleGetMediaUrl = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseGetMediaUrlBody(data);
  const url = await getS3MediaUrl(body.key);

  await postToConnection(
    client.connectionId,
    JSON.stringify({ type: 'mediaUrl', payload: { requestId: body.requestId, key: body.key, url } })
  );

  return { statusCode: 200, body: '' };
};

// ─── deleteMessage ────────────────────────────────────────────────────────────

/**
 * Deletes one of the caller's own sent messages. Scoped to "delete for
 * everyone" on your own messages only — there's no "delete for me"/hide-only
 * variant, and you can never delete someone else's message (enforced by
 * fetching the real item and checking `sender` server-side, never trusting
 * a client-asserted owner).
 *
 * No ack is sent back to the caller — same fire-and-forget shape as
 * `typing`/`markRead` elsewhere in this file. The sender's own client
 * removes the message from its local view optimistically when it issues
 * the delete; the *other* participant learns about it via the
 * `message_deleted` push below.
 */
const handleDeleteMessage = async (client: Client, data: unknown): Promise<APIGatewayProxyResult> => {
  const body = parseDeleteMessageBody(data);

  const existing = await docClient.get({
    TableName: MESSAGES_TABLE,
    Key: { messageId: body.messageId, createdAt: body.createdAt },
  }).promise();

  // Already gone (e.g. a duplicate/retried delete) — treat as success rather
  // than erroring on an already-satisfied request.
  if (!existing.Item) return { statusCode: 200, body: '' };

  const item = existing.Item as { sender: string; nicknameToNickname: string; attachment?: AttachmentMeta };

  if (item.sender !== client.nickname) {
    throw new HandlerError('You can only delete your own messages');
  }
  if (item.nicknameToNickname !== body.chatKey) {
    throw new HandlerError('chatKey does not match this message');
  }

  await docClient.delete({
    TableName: MESSAGES_TABLE,
    Key: { messageId: body.messageId, createdAt: body.createdAt },
  }).promise();

  if (item.attachment?.key) {
    // Best-effort — an orphaned S3 object is a cleanup nit, not worth
    // failing the (already-succeeded) message delete over.
    await deleteMedia(item.attachment.key).catch((e) =>
      console.error('[deleteMessage] Failed to delete S3 object:', sanitizeLog(item.attachment!.key), (e as Error).message)
    );
  }

  const [partA, partB] = body.chatKey.split('#');
  const otherNickname = partA === client.nickname ? partB : partA;
  if (otherNickname) {
    const otherConnectionId = await getConnectionIdByNickname(otherNickname);
    if (otherConnectionId) {
      await postToConnection(
        otherConnectionId,
        JSON.stringify({ type: 'message_deleted', payload: { messageId: body.messageId, chatKey: body.chatKey } })
      ).catch(() => {
        // Stale recipient: postToConnection already cleaned up the record.
      });
    }
  }

  return { statusCode: 200, body: '' };
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Deterministic, alphabetically sorted conversation key.
 * getChatKey('Sam', 'Salman') === getChatKey('Salman', 'Sam') === 'Salman#Sam'
 */
const getChatKey = (a: string, b: string): string => [a, b].sort().join('#');

const sanitizeMessage = (msg: string): string =>
  msg
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

const getClient = async (connectionId: string): Promise<Client> => {
  const out = await docClient.get({ TableName: CLIENTS_TABLE, Key: { connectionId } }).promise();
  if (!out.Item) throw new HandlerError('Client not found');
  return out.Item as Client;
};

/**
 * Returns all connected clients, consuming all DynamoDB Scan pages.
 * NOTE: Scan is acceptable at this scale (<1 000 simultaneous users).
 * At larger scale, replace with a separate counter + paginated Query.
 */
const getAllClients = async (): Promise<Client[]> => {
  const results: Client[] = [];
  let lastKey: AWS.DynamoDB.DocumentClient.Key | undefined;

  do {
    const page = await docClient.scan({
      TableName: CLIENTS_TABLE,
      ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
    }).promise();

    results.push(...((page.Items ?? []) as Client[]));
    lastKey = page.LastEvaluatedKey as AWS.DynamoDB.DocumentClient.Key | undefined;
  } while (lastKey);

  return results;
};

const getUserBySub = async (sub: string): Promise<User | undefined> => {
  const out = await docClient.get({ TableName: USERS_TABLE, Key: { sub } }).promise();
  return out.Item as User | undefined;
};

const getUserByNickname = async (nickname: string): Promise<User | undefined> => {
  const out = await docClient.query({
    TableName: USERS_TABLE,
    IndexName: 'NicknameIndex',
    KeyConditionExpression: '#n = :n',
    ExpressionAttributeNames: { '#n': 'nickname' },
    ExpressionAttributeValues: { ':n': nickname },
    Limit: 1,
  }).promise();
  return out.Items?.[0] as User | undefined;
};

const getConnectionIdByNickname = async (nickname: string): Promise<string | undefined> => {
  const out = await docClient.query({
    TableName: CLIENTS_TABLE,
    IndexName: 'NicknameIndex',
    KeyConditionExpression: '#n = :n',
    ExpressionAttributeNames: { '#n': 'nickname' },
    ExpressionAttributeValues: { ':n': nickname },
    Limit: 1,
  }).promise();
  return out.Items?.[0]?.connectionId as string | undefined;
};

/**
 * Sends a WebSocket frame to a connection.
 * Returns true on success.
 * Returns false and removes the stale record when API Gateway returns 410 Gone.
 * Throws on all other errors.
 */
const postToConnection = async (connectionId: string, data: string): Promise<boolean> => {
  try {
    await apigw.postToConnection({ ConnectionId: connectionId, Data: data }).promise();
    return true;
  } catch (e) {
    if ((e as AWSError).statusCode === 410) {
      console.warn('[ws] Stale connection evicted:', sanitizeLog(connectionId));
      await docClient.delete({ TableName: CLIENTS_TABLE, Key: { connectionId } }).promise();
      return false;
    }
    console.error('[ws] postToConnection error for', sanitizeLog(connectionId), ':', (e as Error).message);
    throw e;
  }
};

/**
 * Probes a connection without sending meaningful data.
 * Used during $connect to detect stale nickname sessions.
 * Returns true if the connection is alive, false if it is stale (and has been evicted).
 */
const probeConnection = async (connectionId: string): Promise<boolean> => {
  try {
    // A zero-byte post is enough to confirm the connection is alive.
    await apigw.postToConnection({ ConnectionId: connectionId, Data: '' }).promise();
    return true;
  } catch (e) {
    if ((e as AWSError).statusCode === 410) {
      await docClient.delete({ TableName: CLIENTS_TABLE, Key: { connectionId } }).promise();
      return false;
    }
    // For any other error (e.g. 5xx from APIGW), assume alive to avoid evicting a valid session.
    console.error('[connect] probeConnection error:', (e as Error).message);
    return true;
  }
};

/**
 * Broadcasts the current online list to all clients except `excludedConnectionId`.
 * Uses the paginated getAllClients so no records are missed.
 */
const notifyClientChange = async (excludedConnectionId = ''): Promise<void> => {
  const clients = await getAllClients();
  const publicList = clients.map(c => ({ nickname: c.nickname }));
  const payload = JSON.stringify({ type: 'clients', payload: publicList });

  await Promise.all(
    clients
      .filter(c => c.connectionId !== excludedConnectionId)
      .map(c => postToConnection(c.connectionId, payload).catch(() => { /* stale — already cleaned up */ }))
  );
};

// ─── Validators ───────────────────────────────────────────────────────────────

const parseAttachment = (value: unknown): AttachmentMeta | undefined => {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object') throw new HandlerError('attachment must be an object');
  const a = value as Record<string, unknown>;
  if (typeof a['key'] !== 'string' || !a['key'].startsWith('chat-media/') || a['key'].includes('..'))
    throw new HandlerError('Invalid attachment key');
  if (typeof a['contentType'] !== 'string' || !EXTENSION_BY_CONTENT_TYPE[a['contentType']])
    throw new HandlerError('Invalid attachment contentType');
  if (typeof a['fileSize'] !== 'number' || !Number.isInteger(a['fileSize']) || a['fileSize'] <= 0 || a['fileSize'] > MAX_ATTACHMENT_BYTES)
    throw new HandlerError('Invalid attachment fileSize');
  const attachment: AttachmentMeta = { key: a['key'], contentType: a['contentType'], fileSize: a['fileSize'] };
  if (a['width'] !== undefined) {
    if (typeof a['width'] !== 'number') throw new HandlerError('attachment.width must be a number');
    attachment.width = a['width'];
  }
  if (a['height'] !== undefined) {
    if (typeof a['height'] !== 'number') throw new HandlerError('attachment.height must be a number');
    attachment.height = a['height'];
  }
  if (a['duration'] !== undefined) {
    if (typeof a['duration'] !== 'number') throw new HandlerError('attachment.duration must be a number');
    attachment.duration = a['duration'];
  }
  if (a['fileName'] !== undefined) {
    if (typeof a['fileName'] !== 'string') throw new HandlerError('attachment.fileName must be a string');
    attachment.fileName = a['fileName'].slice(0, 256);
  }
  return attachment;
};

const parseSendMessageBody = (data: unknown): SendMessageBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing sendMessage payload');
  const d = data as Record<string, unknown>;
  if (typeof d['recipientNickname'] !== 'string' || !d['recipientNickname'].trim())
    throw new HandlerError('recipientNickname is required');
  if (!NICKNAME_RE.test(d['recipientNickname'] as string))
    throw new HandlerError('Invalid recipientNickname format');

  const attachment = parseAttachment(d['attachment']);
  const message = typeof d['message'] === 'string' ? d['message'] : '';
  if (!message.trim() && !attachment) {
    throw new HandlerError('message or attachment is required');
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    throw new HandlerError(`message exceeds ${MAX_MESSAGE_LENGTH} characters`);
  }
  return {
    recipientNickname: d['recipientNickname'] as string,
    message,
    ...(attachment ? { attachment } : {}),
  };
};

const parseGetUploadUrlBody = (data: unknown): GetUploadUrlBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing getUploadUrl payload');
  const d = data as Record<string, unknown>;
  if (typeof d['requestId'] !== 'string' || !d['requestId'].trim())
    throw new HandlerError('requestId is required');
  if (typeof d['contentType'] !== 'string' || !d['contentType'].trim())
    throw new HandlerError('contentType is required');
  if (typeof d['fileSize'] !== 'number' || !Number.isInteger(d['fileSize']) || d['fileSize'] <= 0)
    throw new HandlerError('fileSize must be a positive integer');
  return { requestId: d['requestId'], contentType: d['contentType'], fileSize: d['fileSize'] };
};

const parseDeleteMessageBody = (data: unknown): DeleteMessageBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing deleteMessage payload');
  const d = data as Record<string, unknown>;
  if (typeof d['chatKey'] !== 'string' || !CHAT_KEY_RE.test(d['chatKey'] as string))
    throw new HandlerError('chatKey must be in "NicknameA#NicknameB" format');
  if (typeof d['messageId'] !== 'string' || !d['messageId'].trim())
    throw new HandlerError('messageId is required');
  if (typeof d['createdAt'] !== 'number' || !Number.isInteger(d['createdAt']))
    throw new HandlerError('createdAt must be an integer');
  return { chatKey: d['chatKey'], messageId: d['messageId'], createdAt: d['createdAt'] };
};

const parseGetMediaUrlBody = (data: unknown): GetMediaUrlBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing getMediaUrl payload');
  const d = data as Record<string, unknown>;
  if (typeof d['requestId'] !== 'string' || !d['requestId'].trim())
    throw new HandlerError('requestId is required');
  if (typeof d['key'] !== 'string' || !d['key'].startsWith('chat-media/') || d['key'].includes('..'))
    throw new HandlerError('Invalid key');
  return { requestId: d['requestId'], key: d['key'] };
};

const parseGetMessageBody = (data: unknown): GetMessagesBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing getMessages payload');
  const d = data as Record<string, unknown>;
  if (typeof d['targetNickname'] !== 'string' || !d['targetNickname'].trim())
    throw new HandlerError('targetNickname is required');
  if (!NICKNAME_RE.test(d['targetNickname'] as string))
    throw new HandlerError('Invalid targetNickname format');
  const limit = d['limit'];
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > 100)
    throw new HandlerError('limit must be an integer between 1 and 100');
  if (d['startKey'] !== undefined && (typeof d['startKey'] !== 'object' || d['startKey'] === null))
    throw new HandlerError('startKey must be an object');
  return data as GetMessagesBody;
};

const parseTypingBody = (data: unknown): TypingBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing typing payload');
  const d = data as Record<string, unknown>;
  if (typeof d['recipient'] !== 'string' || !d['recipient'].trim())
    throw new HandlerError('recipient is required');
  if (!NICKNAME_RE.test(d['recipient'] as string))
    throw new HandlerError('Invalid recipient format');
  if (typeof d['isTyping'] !== 'boolean')
    throw new HandlerError('isTyping must be a boolean');
  return data as TypingBody;
};

const parseMarkReadBody = (data: unknown): MarkReadBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing markRead payload');
  const d = data as Record<string, unknown>;
  if (typeof d['chatKey'] !== 'string' || !CHAT_KEY_RE.test(d['chatKey'] as string))
    throw new HandlerError('chatKey must be in "NicknameA#NicknameB" format');
  return data as MarkReadBody;
};

const parseUpdateNicknameBody = (data: unknown): UpdateNicknameBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing updateNickname payload');
  const d = data as Record<string, unknown>;
  if (typeof d['nickname'] !== 'string' || !d['nickname'].trim())
    throw new HandlerError('nickname is required');
  return { nickname: (d['nickname'] as string).trim() };
};
