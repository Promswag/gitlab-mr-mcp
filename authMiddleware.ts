import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const AUTH_KEY_PATH = process.env.REMOTE_GITLAB_MCP_AUTH_KEY_PATH;
if (!AUTH_KEY_PATH) {
  console.error(
    'Error: REMOTE_GITLAB_MCP_AUTH_KEY_PATH environment variable is not set.'
  );
  process.exit(1);
}

const PUBLIC_KEY = fs.readFileSync(
  fileURLToPath(new URL(AUTH_KEY_PATH, import.meta.url)),
  'utf8'
);

export function authenticateJWT(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res
      .status(401)
      .json({ message: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],
    }) as JwtPayload;
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}
