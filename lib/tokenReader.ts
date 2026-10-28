import jwt from 'jsonwebtoken'

export const readToken = (token: string, key: string) => jwt.verify(token, key, { algorithms: ['none', 'HS256'] })
