serverless endpoint: wss://o3tx97i0uc.execute-api.us-east-1.amazonaws.com/dev

websocat "wss://o3tx97i0uc.execute-api.us-east-1.amazonaws.com/dev?nickname=ibrahim"

npx serverless logs -f websocketHandler -t   

control + c to close terminal websocat

npx serverless deploy

wss://o3tx97i0uc.execute-api.us-east-1.amazonaws.com/dev

rm -rf .serverless

npx serverless deploy

{"action":"sendMessage","data":{"recipientNickname":"ali","message":"hello"}}

wss://o3tx97i0uc.execute-api.us-east-1.amazonaws.com/dev

{"action":"sendMessage","data":{"recipientNickname":"ibrahim","message":"hello"}}

websocat "wss://o3tx97i0uc.execute-api.us-east-1.amazonaws.com/dev?nickname=ali"

{"action":"sendMessage","data":{"recipientNickname":"ali","message":"is the websocat messaging test working?"}}

{"action":"sendMessage","data":{"recipientNickname":"ali","message":"this is the first message from ibrahim"}}