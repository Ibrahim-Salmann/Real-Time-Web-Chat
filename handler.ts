import {
  APIGatewayProxyEventQueryStringParameters,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import AWS, { AWSError } from 'aws-sdk';
import { v4 } from 'uuid';

// ─── Types ────────────────────────────────────────────────────────────────────

type APIGatewayRouteKey =
  | '$connect'
  | '$disconnect'
  | '$default'
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'
  | 'typing'
  | 'markRead';

type ClientMessageAction =
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'
  | 'typing'
  | 'markRead';

/**
 * Message Echo Strategy: Option B — sender does NOT receive an echo.
 * The frontend uses optimistic updates; echoing would cause duplicate messages.
 */

type MessageStatus = 'sent' | 'delivered' | 'read';

type Client = {
  connectionId: string;
  nickname: string;
  ttl?: number;
};

type ClientMessage = {
  action: ClientMessageAction;
  data?: any;
};

type SendMessageBody = {
  recipientNickname: string;
  message: string;
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

// ─── Constants ────────────────────────────────────────────────────────────────

const CLIENTS_TABLE_NAME = 'Clients';
const MESSAGES_TABLE_NAME = 'Messages';
const MAX_MESSAGE_LENGTH = 2000;
const NICKNAME_PATTERN = /^[a-zA-Z0-9_-]{1,32}$/;

// ─── AWS Clients ──────────────────────────────────────────────────────────────

const docClient = new AWS.DynamoDB.DocumentClient({
  region: process.env.AWS_REGION || 'us-east-1',
});

const apiGatewayEndpoint = process.env.WSSAPIGATEWAYENDPOINT;
if (!apiGatewayEndpoint) {
  throw new Error('WSSAPIGATEWAYENDPOINT environment variable is required');
}
const apigw = new AWS.ApiGatewayManagementApi({ endpoint: apiGatewayEndpoint });

// ─── Error ────────────────────────────────────────────────────────────────────

class HandlerError extends Error {}

// ─── Entry Point ──────────────────────────────────────────────────────────────

export const handle = async (
  event: APIGatewayProxyEvent,
  _context: Context
): Promise<APIGatewayProxyResult> => {
  const routeKey = event.requestContext.routeKey as APIGatewayRouteKey;
  const connectionId = (event.requestContext.connectionId ?? '').replace(/[\r\n]/g, '');

  try {
    switch (routeKey) {
      case '$connect':
        return await handleConnect(connectionId, event.queryStringParameters);
      case '$disconnect':
        return await handleDisconnect(connectionId);
      case '$default':
      case 'sendMessage':
      case 'getMessages':
      case 'getClients':
      case 'typing':
      case 'markRead':
        return await handleDefaultRoute(connectionId, event.body);
      default:
        return { statusCode: 400, body: JSON.stringify({ message: `Unknown route: ${routeKey}` }) };
    }
  } catch (error) {
    if (error instanceof HandlerError) {
      return { statusCode: 400, body: JSON.stringify({ message: error.message }) };
    }
    console.error('[handler] Unhandled error:', error);
    return { statusCode: 500, body: JSON.stringify({ message: 'Internal server error' }) };
  }
};

// ─── Default Route Dispatcher ─────────────────────────────────────────────────

const handleDefaultRoute = async (
  connectionId: string,
  bodyString: string | null
): Promise<APIGatewayProxyResult> => {
  let clientMessage: ClientMessage;

  try {
    const parsed = JSON.parse(bodyString || '{}');
    if (!parsed.action) throw new HandlerError('Missing "action" field');
    const validActions: ClientMessageAction[] = ['sendMessage', 'getMessages', 'getClients', 'typing', 'markRead'];
    if (!validActions.includes(parsed.action)) throw new HandlerError(`Unknown action: ${parsed.action}`);
    clientMessage = parsed as ClientMessage;
  } catch (e) {
    if (e instanceof SyntaxError) throw new HandlerError('Invalid JSON body');
    throw e;
  }

  const needsClient = clientMessage.action !== 'getClients';
  const client = needsClient ? await getClient(connectionId) : undefined;

  switch (clientMessage.action) {
    case 'sendMessage':
      if (!client) throw new HandlerError('Client not found');
      return await handleSendMessage(client, clientMessage.data);
    case 'getMessages':
      if (!client) throw new HandlerError('Client not found');
      return await handleGetMessages(client, clientMessage.data);
    case 'getClients':
      return await handleGetClients(connectionId);
    case 'typing':
      if (!client) throw new HandlerError('Client not found');
      return await handleTyping(client, clientMessage.data);
    case 'markRead':
      if (!client) throw new HandlerError('Client not found');
      return await handleMarkRead(client, clientMessage.data);
    default:
      throw new HandlerError(`Unhandled action`);
  }
};

// ─── Connect ──────────────────────────────────────────────────────────────────

const handleConnect = async (
  connectionId: string,
  queryParams: APIGatewayProxyEventQueryStringParameters | null
): Promise<APIGatewayProxyResult> => {
  const nickname = queryParams?.nickname;

  if (!nickname) {
    return { statusCode: 400, body: JSON.stringify({ message: 'Nickname is required' }) };
  }

  if (!NICKNAME_PATTERN.test(nickname)) {
    return { statusCode: 400, body: JSON.stringify({ message: 'Nickname must be 1–32 alphanumeric/_/- characters' }) };
  }

  const existingConnectionId = await getConnectionIdByNickname(nickname);
  if (existingConnectionId) {
    return { statusCode: 409, body: JSON.stringify({ message: `Nickname '${nickname}' is already in use` }) };
  }

  await docClient.put({
    TableName: CLIENTS_TABLE_NAME,
    Item: {
      connectionId,
      nickname,
      ttl: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    },
  }).promise();

  console.info(`[connect] nickname=${nickname} connectionId=${connectionId}`);

  await notifyClientChange(connectionId);

  return { statusCode: 200, body: JSON.stringify({ message: 'Connected' }) };
};

// ─── Disconnect ───────────────────────────────────────────────────────────────

const handleDisconnect = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  const client = await getClient(connectionId).catch(() => null);

  if (client) {
    await docClient.delete({
      TableName: CLIENTS_TABLE_NAME,
      Key: { connectionId },
    }).promise();

    console.info(`[disconnect] nickname=${client.nickname} connectionId=${connectionId}`);
    await notifyClientChange(connectionId);
  }

  return { statusCode: 200, body: JSON.stringify({ message: 'Disconnected' }) };
};

// ─── Send Message ─────────────────────────────────────────────────────────────

const handleSendMessage = async (
  client: Client,
  data: any
): Promise<APIGatewayProxyResult> => {
  const body = parseSendMessageBody(data);

  if (body.recipientNickname === client.nickname) {
    throw new HandlerError('Cannot send a message to yourself');
  }

  const sanitized = sanitizeMessage(body.message);
  const chatKey = getChatKey(client.nickname, body.recipientNickname);
  const messageId = v4();
  const createdAt = Date.now();

  // Status starts as 'sent'; upgraded to 'delivered' if recipient is online now.
  let status: MessageStatus = 'sent';

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
        },
      })
    );
    if (delivered) status = 'delivered';
  }

  // Persist with final status
  await docClient.put({
    TableName: MESSAGES_TABLE_NAME,
    Item: {
      messageId,
      nicknameToNickname: chatKey,
      message: sanitized,
      sender: client.nickname,
      createdAt,
      status,
    },
  }).promise();

  // Notify sender of the status (Option B: no echo, only status update)
  await postToConnection(
    client.connectionId,
    JSON.stringify({
      type: 'message_status_update',
      payload: { messageId, chatKey, status },
    })
  );

  return { statusCode: 200, body: '' };
};

// ─── Get Messages ─────────────────────────────────────────────────────────────

const handleGetMessages = async (
  client: Client,
  data: any
): Promise<APIGatewayProxyResult> => {
  const body = parseGetMessageBody(data);
  const chatKey = getChatKey(client.nickname, body.targetNickname);

  const queryInput: AWS.DynamoDB.DocumentClient.QueryInput = {
    TableName: MESSAGES_TABLE_NAME,
    IndexName: 'NicknameToNicknameIndex',
    KeyConditionExpression: '#ntn = :ntn',
    ExpressionAttributeNames: { '#ntn': 'nicknameToNickname' },
    ExpressionAttributeValues: { ':ntn': chatKey },
    Limit: body.limit,
    ScanIndexForward: false,
  };

  if (body.startKey) {
    queryInput.ExclusiveStartKey = body.startKey;
  }

  const output = await docClient.query(queryInput).promise();

  await postToConnection(
    client.connectionId,
    JSON.stringify({
      type: 'messages',
      payload: {
        chatKey,
        messages: output.Items ?? [],
        lastEvaluatedKey: output.LastEvaluatedKey,
      },
    })
  );

  return { statusCode: 200, body: '' };
};

// ─── Get Clients ──────────────────────────────────────────────────────────────

const handleGetClients = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  const allClients = await getAllClients();
  await postToConnection(
    connectionId,
    JSON.stringify({
      type: 'clients',
      payload: allClients.map(c => ({ nickname: c.nickname })),
    })
  );
  return { statusCode: 200, body: '' };
};

// ─── Typing Indicator ─────────────────────────────────────────────────────────

const handleTyping = async (
  client: Client,
  data: any
): Promise<APIGatewayProxyResult> => {
  const body = parseTypingBody(data);

  const recipientConnectionId = await getConnectionIdByNickname(body.recipient);
  if (recipientConnectionId) {
    // Forward only to target — never persisted
    await postToConnection(
      recipientConnectionId,
      JSON.stringify({
        type: 'typing',
        payload: {
          sender: client.nickname,
          isTyping: body.isTyping,
        },
      })
    );
  }

  return { statusCode: 200, body: '' };
};

// ─── Mark Read ────────────────────────────────────────────────────────────────

/**
 * When a recipient opens a conversation, the frontend sends markRead with the chatKey.
 * The server updates all 'delivered' messages in that chat to 'read' and notifies the sender.
 */
const handleMarkRead = async (
  client: Client,
  data: any
): Promise<APIGatewayProxyResult> => {
  const body = parseMarkReadBody(data);

  // Validate that this client is a participant in the chatKey
  const parts = body.chatKey.split('#');
  if (parts.length !== 2 || !parts.includes(client.nickname)) {
    throw new HandlerError('Invalid chatKey for this client');
  }

  const otherNickname = parts.find(p => p !== client.nickname)!;

  // Fetch delivered messages in this conversation where the current client is the recipient
  const output = await docClient.query({
    TableName: MESSAGES_TABLE_NAME,
    IndexName: 'NicknameToNicknameIndex',
    KeyConditionExpression: '#ntn = :ntn',
    FilterExpression: '#status = :delivered AND #sender <> :me',
    ExpressionAttributeNames: {
      '#ntn': 'nicknameToNickname',
      '#status': 'status',
      '#sender': 'sender',
    },
    ExpressionAttributeValues: {
      ':ntn': body.chatKey,
      ':delivered': 'delivered',
      ':me': client.nickname,
    },
  }).promise();

  const items = output.Items ?? [];
  if (items.length === 0) return { statusCode: 200, body: '' };

  // Update each to 'read'
  await Promise.all(
    items.map(item =>
      docClient.update({
        TableName: MESSAGES_TABLE_NAME,
        Key: { messageId: item['messageId'], createdAt: item['createdAt'] },
        UpdateExpression: 'SET #status = :read',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':read': 'read' },
      }).promise()
    )
  );

  // Notify the original sender (otherNickname) of the read status
  const senderConnectionId = await getConnectionIdByNickname(otherNickname);
  if (senderConnectionId) {
    const messageIds = items.map(i => i['messageId'] as string);
    await postToConnection(
      senderConnectionId,
      JSON.stringify({
        type: 'message_status_update',
        payload: {
          chatKey: body.chatKey,
          messageIds,
          status: 'read',
        },
      })
    );
  }

  return { statusCode: 200, body: '' };
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Deterministic conversation key — always alphabetically sorted.
 * "Sam#Salman" and "Salman#Sam" both resolve to "Salman#Sam".
 */
const getChatKey = (a: string, b: string): string => [a, b].sort().join('#');

const sanitizeMessage = (message: string): string =>
  message
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

const getClient = async (connectionId: string): Promise<Client> => {
  const output = await docClient.get({ TableName: CLIENTS_TABLE_NAME, Key: { connectionId } }).promise();
  if (!output.Item) throw new HandlerError('Client not found');
  return output.Item as Client;
};

const getAllClients = async (): Promise<Client[]> => {
  const output = await docClient.scan({ TableName: CLIENTS_TABLE_NAME }).promise();
  return (output.Items ?? []) as Client[];
};

const getConnectionIdByNickname = async (nickname: string): Promise<string | undefined> => {
  const output = await docClient.query({
    TableName: CLIENTS_TABLE_NAME,
    IndexName: 'NicknameIndex',
    KeyConditionExpression: '#nickname = :nickname',
    ExpressionAttributeNames: { '#nickname': 'nickname' },
    ExpressionAttributeValues: { ':nickname': nickname },
  }).promise();
  return output.Items?.[0]?.connectionId as string | undefined;
};

/**
 * Posts to a WebSocket connection.
 * Returns false and cleans up stale connections (HTTP 410 Gone).
 */
const postToConnection = async (connectionId: string, messageBody: string): Promise<boolean> => {
  try {
    await apigw.postToConnection({ ConnectionId: connectionId, Data: messageBody }).promise();
    return true;
  } catch (e) {
    if ((e as AWSError).statusCode === 410) {
      console.warn(`[postToConnection] Stale connection removed: ${connectionId}`);
      await docClient.delete({ TableName: CLIENTS_TABLE_NAME, Key: { connectionId } }).promise();
      return false;
    }
    console.error('[postToConnection] Failed to post:', (e as Error).message);
    throw e;
  }
};

/**
 * Broadcasts the updated client list to all connected clients except the excluded one.
 */
const notifyClientChange = async (excludedConnectionId = '') => {
  const clients = await getAllClients();
  const publicList = clients.map(c => ({ nickname: c.nickname }));

  await Promise.all(
    clients
      .filter(c => c.connectionId !== excludedConnectionId)
      .map(c =>
        postToConnection(c.connectionId, JSON.stringify({ type: 'clients', payload: publicList }))
      )
  );
};

// ─── Validators ───────────────────────────────────────────────────────────────

const parseSendMessageBody = (data: any): SendMessageBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing message data');
  if (typeof data.recipientNickname !== 'string' || !data.recipientNickname.trim()) {
    throw new HandlerError('recipientNickname is required');
  }
  if (!NICKNAME_PATTERN.test(data.recipientNickname)) {
    throw new HandlerError('Invalid recipientNickname format');
  }
  if (typeof data.message !== 'string' || !data.message.trim()) {
    throw new HandlerError('message is required and cannot be empty');
  }
  if (data.message.length > MAX_MESSAGE_LENGTH) {
    throw new HandlerError(`message exceeds maximum length of ${MAX_MESSAGE_LENGTH}`);
  }
  return data as SendMessageBody;
};

const parseGetMessageBody = (data: any): GetMessagesBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing getMessages data');
  if (typeof data.targetNickname !== 'string' || !data.targetNickname.trim()) {
    throw new HandlerError('targetNickname is required');
  }
  if (!NICKNAME_PATTERN.test(data.targetNickname)) {
    throw new HandlerError('Invalid targetNickname format');
  }
  if (!data.limit || typeof data.limit !== 'number' || data.limit < 1 || data.limit > 100) {
    throw new HandlerError('limit must be a number between 1 and 100');
  }
  if (data.startKey !== undefined && typeof data.startKey !== 'object') {
    throw new HandlerError('startKey must be an object');
  }
  return data as GetMessagesBody;
};

const parseTypingBody = (data: any): TypingBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing typing data');
  if (typeof data.recipient !== 'string' || !data.recipient.trim()) {
    throw new HandlerError('recipient is required');
  }
  if (!NICKNAME_PATTERN.test(data.recipient)) {
    throw new HandlerError('Invalid recipient format');
  }
  if (typeof data.isTyping !== 'boolean') {
    throw new HandlerError('isTyping must be a boolean');
  }
  return data as TypingBody;
};

const parseMarkReadBody = (data: any): MarkReadBody => {
  if (!data || typeof data !== 'object') throw new HandlerError('Missing markRead data');
  if (typeof data.chatKey !== 'string' || !data.chatKey.includes('#')) {
    throw new HandlerError('chatKey is required and must be in "A#B" format');
  }
  return data as MarkReadBody;
};
