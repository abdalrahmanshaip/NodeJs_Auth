import jwt from 'jsonwebtoken'

export const verifyToken = (req, res, next) => {
  const token = req.cookies['accessToken']
  if (!token) return res.status(401).json({ message: 'Access Denied' })
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_ACCESSTOKEN)
    req.email = decoded.email
    next()
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
}
export const verifyRefresh = (email, token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_REFRESHTOKEN)
    console.log(decoded)
    return decoded.email === email
  } catch (error) {
    console.error(error)
    return false
  }
}
