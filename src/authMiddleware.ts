import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

export function authenticateJWT(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const RAW_KEY = process.env.REMOTE_GITLAB_MCP_PUBLIC_KEY;
  if (!RAW_KEY) {
    console.error(
      'Error: REMOTE_GITLAB_MCP_PUBLIC_KEY environment variable is not set.'
    );
    process.exit(1);
  }
  const PUBLIC_KEY = RAW_KEY.replace(/\\n/g, '\n')
  
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
