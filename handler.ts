import {
  APIGatewayProxyEventQueryStringParameters,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import AWS, { AWSError } from 'aws-sdk';
import { v4 } from 'uuid'; // Import v4 for UUID generation

// New type for API Gateway's routeKey (what API Gateway routes on)
type APIGatewayRouteKey =
  | '$connect'
  | '$disconnect'
  | '$default'
  | 'sendMessage'
  | 'getMessages'
  | 'getClients';

// New type for the 'action' field within the client's JSON message body (for internal routing)
type ClientMessageAction =
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'

type Client = {
  connectionId: string;
  nickname: string;
  ttl?: number; // Added for DynamoDB TTL
};

// Type for the client's incoming JSON message
type ClientMessage = {
  action: ClientMessageAction;
  data?: any; // Data can be any structure depending on the action
};

// Type for messages sent from server to client
type ServerToClientMessage = {
  type: string;
  payload: any;
};

// type Client = {
//   connectionId: string;
//   nickname: string;
// };

type SendMessageBody = {
  recipientNickname: string;
  message: string;
};

type GetMessagesBody = {
  targetNickname: string;
  startKey: AWS.DynamoDB.DocumentClient.Key | undefined;
  limit: number;
};

const CLIENTS_TABLE_NAME = "Clients";
const MESSAGES_TABLE_NAME = "Messages";
  
const docClient = new AWS.DynamoDB.DocumentClient();
const apiGatewayEndpoint = process.env.WSSAPIGATEWAYENDPOINT;
if (!apiGatewayEndpoint) {
  throw new Error('WSSAPIGATEWAYENDPOINT environment variable is required');
}
const apigw = new AWS.ApiGatewayManagementApi({
  endpoint: apiGatewayEndpoint,
});

class HandlerError extends Error {}

export const handle = async (
  event: APIGatewayProxyEvent, // APIGatewayProxyEvent contains requestContext, body, queryStringParameters
  context: Context // Context object provides runtime information
): Promise<APIGatewayProxyResult> => {

  console.log("routeKey:", event.requestContext.routeKey);
  console.log("body:", event.body);
  console.log("queryString:", event.queryStringParameters);
  console.log("connectionId:", event.requestContext.connectionId);

  const routeKey = event.requestContext.routeKey as APIGatewayRouteKey; // Cast to new APIGatewayRouteKey type
  const connectionId = (event.requestContext.connectionId ?? '').replace(/[\r\n]/g, ''); // CWE-117 Protection: Remove CR/LF from connectionId
  
  console.log(`Connection ID: ${connectionId}`);

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
        return await handleDefaultRoute(connectionId, event.body);
      default:
        // This case should ideally not be reached if $default is configured correctly
        // to catch all non-$connect/$disconnect messages.
        console.warn(`Unexpected routeKey: ${routeKey}`);
        return {
          statusCode: 400,
          body: JSON.stringify({ // Return a structured error message
            message: `Unknown route key: ${routeKey}`
          }),
        };
    }

  } catch (error) {

    if (error instanceof HandlerError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: error.message }),
      };
    }

    console.error(error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Internal server error',
      }),
    };
  }
};

// New handler for the $default route, responsible for internal message routing
const handleDefaultRoute = async (
  connectionId: string,
  bodyString: string | null
): Promise<APIGatewayProxyResult> => {
  let clientMessage: ClientMessage;

  try {
    const parsedBody = JSON.parse(bodyString || '{}');
    if (!parsedBody.action) {
      throw new HandlerError('Missing "action" field in message body');
    }
    // Validate action type to ensure it's one of our expected actions
    if (!['sendMessage', 'getMessages', 'getClients'].includes(parsedBody.action)) {
        throw new HandlerError(`Unknown action: ${parsedBody.action}`);
    }
    clientMessage = parsedBody as ClientMessage;
  } catch (e) {
    if (e instanceof SyntaxError) {
      throw new HandlerError('Invalid JSON message body');
    }
    throw e; // Re-throw HandlerError or other unexpected errors
  }

  // For application-specific actions, we usually need the client's identity
  // Fetch client details once if needed by multiple actions.
  // getClients might not strictly need the full client object, just connectionId.
  let client: Client | undefined;
  if (clientMessage.action !== 'getClients') {
      console.log("Fetching client for connectionId:", connectionId);
      client = await getClient(connectionId);
      console.log("Fetched client:", client);
  }

  console.log("parsed clientMessage:", clientMessage);
  console.log("parsed action:", clientMessage.action);
  console.log("parsed data:", clientMessage.data);

  switch (clientMessage.action) {
    case 'sendMessage':
      console.log("ENTERING sendMessage CASE");
      if (!client) throw new HandlerError('Client not found for sendMessage'); // Ensure client exists
      console.log("CLIENT:", client);
      return await handleSendMessage(client, clientMessage.data);
    case 'getMessages':
      if (!client) throw new HandlerError('Client not found for getMessages'); // Ensure client exists
      return await handleGetMessages(client, clientMessage.data);
    case 'getClients':
      return await handleGetClients(connectionId);
    default:
      throw new HandlerError(`Unhandled action: ${clientMessage.action}`); // Should not be reached due to prior validation
  }
};



const handleConnect = async (
  connectionId: string,
  queryParams: APIGatewayProxyEventQueryStringParameters | null
): Promise<APIGatewayProxyResult> => {
  const nickname = queryParams?.nickname;

  if (!nickname) {
    return {
      statusCode: 400,
      body: JSON.stringify({ message: 'Nickname is required' }),
    };
  }

  // Check if nickname already exists
  const existingClient = await getConnectionIdByNickname(nickname);
  if (existingClient) {
    // If nickname is already in use, reject connection.
    // Note: API Gateway $connect doesn't allow custom error messages to client easily.
    // The client might just see a connection failure.
    return {
      statusCode: 409, // Conflict
      body: JSON.stringify({ message: `Nickname '${nickname}' is already in use.` }),
    };
  }

  await docClient.put({
    TableName: CLIENTS_TABLE_NAME,
    Item: {
      connectionId,
      nickname,
      ttl: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7), // Set TTL to 7 days for automatic cleanup
    },
  }).promise();

  // Notify ALL clients (including the newly connected one) about the updated client list.
  // This ensures the new client immediately sees other users and others see the new client.
  await notifyClientChange();

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Connected',
    }),
  };
};

const handleDisconnect = async (
  connectionId: string
): Promise<APIGatewayProxyResult> => {
  // First, get the client's nickname before deleting to ensure we have context for notification
  const client = await getClient(connectionId).catch(() => null); // Handle case where client might already be gone
  if (client) {
    await docClient.delete({
      TableName: CLIENTS_TABLE_NAME,
      Key: {
        connectionId,
      },
    }).promise();

    // Notify other clients about the change, excluding the disconnected one.
    // The client is already deleted from DynamoDB, so getAllClients() won't include them.
    // We pass connectionId as a safety net to avoid sending to a potentially stale connection.
    await notifyClientChange(connectionId);
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Disconnected',
    }),
  };
};

const handleSendMessage = async (
  client: Client,
  data: any // Now receives the 'data' part of the client message
): Promise<APIGatewayProxyResult> => {

  console.log("handleSendMessage data:", data);

  const body = parseSendMessageBody(data); // Parse and validate the data
  // CWE-79/80 Mitigation: Simple HTML escaping
  const sanitizedMessage = body.message // Apply sanitization to the message
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const nicknameToNickname = getNicknameToNickname([client.nickname, body.recipientNickname]);

  console.log("SEND MESSAGE FIRED");
  console.log("sender:", client.nickname);
  console.log("recipient:", body.recipientNickname);
  console.log("message:", body.message);

  await docClient.put({
    TableName: MESSAGES_TABLE_NAME,
    Item: {
      messageId: v4(),
      nicknameToNickname,
      message: sanitizedMessage,
      sender: client.nickname,
      createdAt: Date.now(),
    },
  }).promise();

  // Find recipient's connectionId to post the message in real-time is failing because getConnectionIdByNickname is not working as expected. We need to debug it.
  const recipientConnectionId = await getConnectionIdByNickname(body.recipientNickname);

  console.log("recipientConnectionId:", recipientConnectionId);

  if (recipientConnectionId) {
    console.log("Posting message to recipient...");
    await apigw.postToConnection({
      ConnectionId: recipientConnectionId,
      Data: JSON.stringify({
        type: 'message', // Adhere to ServerToClientMessage format
        payload: { // Adhere to ServerToClientMessage format
          sender: client.nickname,
          message: sanitizedMessage,
        },
      }),
    }).promise();
  }

  const allClients = await getAllClients();
  console.log("ALL CLIENTS AT SEND TIME:", allClients);

  return { statusCode: 200, body: '' };
};

const handleGetMessages = async (
  client: Client,
  data: any // Now receives the 'data' part of the client message
): Promise<APIGatewayProxyResult> => {
  const body = parseGetMessageBody(data); // Parse and validate the data
  const queryInput: AWS.DynamoDB.DocumentClient.QueryInput = {
    TableName: MESSAGES_TABLE_NAME,
    IndexName: 'NicknameToNicknameIndex',
    KeyConditionExpression: '#nicknameToNickname = :nicknameToNickname',
    ExpressionAttributeNames: { '#nicknameToNickname': 'nicknameToNickname' },
    ExpressionAttributeValues: {
      ':nicknameToNickname': getNicknameToNickname([client.nickname, body.targetNickname]),
    },
    Limit: body.limit,
    ScanIndexForward: false,
  };

  if (body.startKey) {
    queryInput.ExclusiveStartKey = body.startKey;
  }

  const output = await docClient.query(queryInput).promise();

  await postToConnection(client.connectionId, JSON.stringify({
    type: 'messages', // Adhere to ServerToClientMessage format
    payload: { // Adhere to ServerToClientMessage format
      messages: output.Items ?? [],
      lastEvaluatedKey: output.LastEvaluatedKey,
    },
  }));

  return { statusCode: 200, body: '' };
};

const handleGetClients = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  const allClients = await getAllClients();
  const publicClientList = allClients.map(c => ({ nickname: c.nickname })); // Sanitize for public view
  await postToConnection(connectionId, JSON.stringify({
    type: 'clients',
    payload: publicClientList, // Adhere to ServerToClientMessage format
  }));
  return { statusCode: 200, body: '' };
};

// --- Helpers ---

const getClient = async (connectionId: string): Promise<Client> => {
  console.log("DynamoDB GET connectionId:", connectionId);
  const output = await docClient.get({ TableName: CLIENTS_TABLE_NAME, Key: { connectionId } }).promise();
  console.log("DynamoDB GET output:", output);
  if (!output.Item) throw new HandlerError('client does not exist');
  return output.Item as Client;
};

const getAllClients = async (): Promise<Client[]> => {
  const output = await docClient.scan({ TableName: CLIENTS_TABLE_NAME }).promise();
  console.log("DEBUG ALL CLIENTS:", output.Items);
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
  return output.Items?.[0]?.connectionId;
};

const postToConnection = async (connectionId: string, messageBody: string): Promise<boolean> => {
  try {
    console.log("Posting to connection:", connectionId);
    console.log("Message body:", messageBody);
    await apigw.postToConnection({ ConnectionId: connectionId, Data: messageBody }).promise();
    return true;
  } catch (e) {
    if ((e as AWSError).statusCode === 410) {
      await docClient.delete({ TableName: CLIENTS_TABLE_NAME, Key: { connectionId } }).promise();
      return false;
    }
    throw e;
  }
};

// Notifies all active clients about changes in the client list.
// excludedConnectionId: If provided, this connection will not receive the update (e.g., a disconnected client).
const notifyClientChange = async (excludedConnectionId: string = '') => {
  const clients = await getAllClients();
  // Sanitize the list to avoid leaking sensitive connectionIds to other users
  const publicClientList = clients.map(c => ({ nickname: c.nickname }));

  await Promise.all(clients.map(async (c) => {
    // Skip the excluded connection (stale/disconnected), notify everyone else
    if (excludedConnectionId !== c.connectionId) {
      await postToConnection(c.connectionId, JSON.stringify({ type: 'clients', payload: publicClientList })); // Adhere to ServerToClientMessage format
    }
  }));
};

// Parses and validates the incoming data for sendMessage action.
// It now accepts 'any' as input, as it's already parsed JSON from handleDefaultRoute.
const parseSendMessageBody = (data: any): SendMessageBody => {
  if (!data || typeof data !== 'object' || !data.recipientNickname || !data.message) {
    throw new HandlerError('invalid SendMessageBody: recipientNickname and message are required');
  }
  return data as SendMessageBody;
};

// Parses and validates the incoming data for getMessages action.
// It now accepts 'any' as input, as it's already parsed JSON from handleDefaultRoute.
const parseGetMessageBody = (data: any): GetMessagesBody => {
  if (!data || typeof data !== 'object' || !data.targetNickname || !data.limit) {
    throw new HandlerError('invalid GetMessageBody: targetNickname and limit are required');
  }
  // Ensure startKey is correctly typed if present
  if (data.startKey && typeof data.startKey !== 'object') {
      throw new HandlerError('invalid GetMessageBody: startKey must be an object');
  }
  return data as GetMessagesBody;
};

const getNicknameToNickname = (nicknames: string[]) =>
  nicknames.sort().join('#');