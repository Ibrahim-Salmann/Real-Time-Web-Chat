import {
  APIGatewayProxyEventQueryStringParameters,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import AWS, { AWSError } from 'aws-sdk';
import { v4 } from 'uuid';

type Action =
  | 'sendMessage'
  | 'getMessages'
  | 'getClients'
  | '$connect'
  | '$disconnect';

type Client = {
  connectionId: string;
  nickname: string;
};

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
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {

  const routeKey = event.requestContext.routeKey as Action;
  const connectionId = (event.requestContext.connectionId ?? '').replace(/[\r\n]/g, ''); // CWE-117 Protection

  console.log(`Connection ID: ${connectionId}`);

  try {
    switch (routeKey) {
      case '$connect':
        return await handleConnect(connectionId, event.queryStringParameters);
      case '$disconnect':
        return await handleDisconnect(connectionId);
      case 'sendMessage':
        return await handleSendMessage(
          await getClient(connectionId),
          parseSendMessageBody(event.body)
        );
      case 'getMessages':
        return await handleGetMessages(
          await getClient(connectionId),
          parseGetMessageBody(event.body)
        );
      case 'getClients':
        return await handleGetClients(connectionId);
      default:
        return {
          statusCode: 400,
          body: JSON.stringify({
            message: 'Unknown route'
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

  await docClient.put({
    TableName: CLIENTS_TABLE_NAME,
    Item: {
      connectionId,
      nickname,
    },
  }).promise();

  // No argument = notify ALL clients including the newly connected one,
  // so they immediately receive the up-to-date client list.
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
  await docClient.delete({
    TableName: CLIENTS_TABLE_NAME,
    Key: {
      connectionId,
    },
  }).promise();

  // Pass connectionId so notifyClientChange skips this dead connection.
  // The client is already deleted from DynamoDB above, so getAllClients()
  // won't include them — but we exclude by connectionId as a safety net.
  await notifyClientChange(connectionId);

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Disconnected',
    }),
  };
};

const handleSendMessage = async (
  client: Client,
  body: SendMessageBody
): Promise<APIGatewayProxyResult> => {
  // CWE-79/80 Mitigation: Simple HTML escaping
  const sanitizedMessage = body.message
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const nicknameToNickname = getNicknameToNickname([client.nickname, body.recipientNickname]);

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

  const recipientConnectionId = await getConnectionIdByNickname(body.recipientNickname);

  if (recipientConnectionId) {
    await apigw.postToConnection({
      ConnectionId: recipientConnectionId,
      Data: JSON.stringify({
        type: 'message',
        value: {
          sender: client.nickname,
          message: sanitizedMessage,
        },
      }),
    }).promise();
  }

  return { statusCode: 200, body: '' };
};

const handleGetMessages = async (
  client: Client,
  body: GetMessagesBody
): Promise<APIGatewayProxyResult> => {
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
    type: 'messages',
    value: {
      messages: output.Items ?? [],
      lastEvaluatedKey: output.LastEvaluatedKey,
    },
  }));

  return { statusCode: 200, body: '' };
};

const handleGetClients = async (connectionId: string): Promise<APIGatewayProxyResult> => {
  await postToConnection(connectionId, JSON.stringify({
    type: 'clients',
    value: await getAllClients(),
  }));
  return { statusCode: 200, body: '' };
};

// --- Helpers ---

const getClient = async (connectionId: string): Promise<Client> => {
  const output = await docClient.get({ TableName: CLIENTS_TABLE_NAME, Key: { connectionId } }).promise();
  if (!output.Item) throw new HandlerError('client does not exist');
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
  return output.Items?.[0]?.connectionId;
};

const postToConnection = async (connectionId: string, messageBody: string): Promise<boolean> => {
  try {
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

// excludedConnectionId defaults to '' so passing no argument notifies ALL clients.
// On connect: call with no arg so the new client also receives the updated list.
// On disconnect: call with the departed connectionId to skip sending to a dead connection.
const notifyClientChange = async (excludedConnectionId: string = '') => {
  const clients = await getAllClients();
  // Sanitize the list to avoid leaking connectionIds to other users
  const publicClientList = clients.map(c => ({ nickname: c.nickname }));

  await Promise.all(clients.map(async (c) => {
    // Skip the excluded connection (stale/disconnected), notify everyone else
    if (excludedConnectionId !== c.connectionId) {
      await postToConnection(c.connectionId, JSON.stringify({ type: 'clients', value: publicClientList }));
    }
  }));
};

const parseSendMessageBody = (body: string | null): SendMessageBody => {
  const data = JSON.parse(body || '{}');
  if (!data.recipientNickname || !data.message) throw new HandlerError('invalid SendMessageBody');
  return data as SendMessageBody;
};

const parseGetMessageBody = (body: string | null): GetMessagesBody => {
  const data = JSON.parse(body || '{}');
  if (!data.targetNickname || !data.limit) throw new HandlerError('invalid GetMessageBody');
  return data as GetMessagesBody;
};

const getNicknameToNickname = (nicknames: string[]) => nicknames.sort().join('#');