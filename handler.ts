const handle = async (event: any) => {
  const { routeKey } = event.requestContext;
  const connectionId = event.requestContext.connectionId;

  console.log(`Route: ${routeKey} | Connection: ${connectionId}`);

  switch (routeKey) {
    case '$connect':
      // Logic for new connections (e.g., save connectionId to DDB)
      break;
    case '$disconnect':
      // Logic for disconnections (e.g., remove from DDB)
      break;
    case 'sendMessage':
      // Logic for handling chat messages
      break;
    case 'getMessages':
    case 'getClients':
      // Logic for data retrieval
      break;
  }

  return { statusCode: 200 };
};


