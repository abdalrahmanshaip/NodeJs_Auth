import jwt from 'jsonwebtoken'
export const jwtGeneration = (payload) => {
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET_ACCESSTOKEN, {
    expiresIn: '10m',
  })
  const refreshToken = jwt.sign(payload, process.env.JWT_SECRET_REFRESHTOKEN, {
    expiresIn: '1d',
  })
  return { accessToken, refreshToken }
}
