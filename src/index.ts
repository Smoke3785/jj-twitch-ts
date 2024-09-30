require('dotenv').config();

// Dependencies
import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import cors from 'cors';

// Types
import type { JwtPayload } from 'jsonwebtoken';

// Instantiation
const app = express();
app.use(cors({ origin: 'https://client.twitch.tv' }));

// Constants
const TWITCH_PUBLIC_KEY_URL = 'https://id.twitch.tv/oauth2/keys';
const PORT = process.env.PORT || 3003;

// Memory
let cachedPublicKey: any = null;

// Functions
async function getTwitchPublicKey(): Promise<any> {
  if (cachedPublicKey === null) {
    try {
      const response = await axios.get(TWITCH_PUBLIC_KEY_URL);
      if (response.status === 200) {
        cachedPublicKey = response.data;
      } else {
        throw new Error('Failed to fetch Twitch public keys');
      }
    } catch (error) {
      throw new Error('Failed to fetch Twitch public keys');
    }
  }
  return cachedPublicKey;
}

async function decodeJwt(token: string): Promise<string | JwtPayload | null> {
  try {
    const publicKeyInfo = await getTwitchPublicKey();
    const publicKeys = publicKeyInfo.keys;

    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    const key = publicKeys.find((k: any) => k.kid === decodedHeader?.kid);

    if (!key) {
      throw new Error('Key not found');
    }

    const publicKey = jwt.verify(token, key, {
      audience: process.env.TWITCH_CLIENT_ID, // Replace with client ID
      algorithms: ['RS256'],
    });

    return publicKey;
  } catch (error) {
    console.error(`Error decoding JWT: ${error}`);
    return null;
  }
}

// Server

// Middleware. This runs on all requests which match the path (first parameter). Since the path is a wildcard, it runs on all requests.
// The purpose of this middleware is to log the request method and path to the console. The next() function is called to pass control to the next middleware in the stack.
// Or, since this is the last middleware, to the request handler.
app.use('*', async (req: Request, res: Response, next) => {
  console.log(`Received [${req.method}]`, req.originalUrl);
  next();
});

// Route handler. Conceptually the same as @app.route("/check-role", methods=["GET", "POST"]), except that it's split into separate handlers for each method.

app.get('/check-role', async (req: Request, res: Response) => {
  console.log('Received request');

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authorization header missing or invalid' });
    return;
  }

  // Extract the token from the Authorization header
  const token = authHeader.split(' ')[1];

  res.status(200).json({ Token: token });
  return;
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
