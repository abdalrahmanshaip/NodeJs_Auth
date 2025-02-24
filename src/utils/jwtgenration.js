import jwt from 'jsonwebtoken'
export const jwtGeneration = (payload) => {
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '1d',
  })
  return accessToken
}
