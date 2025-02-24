import User from '../module/userModule.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { jwtGeneration } from '../utils/jwtgenration.js'
import { validationResult } from 'express-validator'
import { verifyRefresh } from '../middleware/authMiddleware.js'

export const getUser = async (req, res) => {
  try {
    const users = await User.find({}, { __v: 0, password: 0 })
    res.status(200).json({ status: 200, message: 'All users', data: users })
  } catch (error) {
    res.status(500).json({ message: 'Server Error' })
  }
}

export const register = async (req, res) => {
  const { name, email, phone, password, role } = req.body
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ status: 400, errors: errors.array() })
  }
  try {
    const userExit = await User.findOne({
      name,
      email,
    })
    if (userExit) {
      return res
        .status(400)
        .json({ status: 400, message: 'User already exist' })
    }

    const hashPassword = await bcrypt.hash(password, 10)
    const user = await User.create({
      name,
      email,
      phone,
      password: hashPassword,
      role,
    })
    await user.save()
    return res.status(201).json({
      status: 201,
      message: 'User created successfully',
    })
  } catch (error) {
    return res.status(500).json({ status: 404, message: error.message })
  }
}

export const login = async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await User.findOne({ email })
    if (!user)
      return res.status(404).json({ status: 404, message: 'User not found' })
    const matchPassword = await bcrypt.compare(password, user.password)
    if (!matchPassword) {
      return res
        .status(400)
        .json({ status: 400, message: 'Invalid credentials' })
    }

    const { accessToken, refreshToken } = jwtGeneration({ email: user.email })
    await res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 3600000,
    })

    return res.status(200).json({
      status: 200,
      message: 'Login successful',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        accessToken,
        refreshToken,
      },
    })
  } catch (error) {
    return res.status(500).json({ status: 500, message: error.message })
  }
}

export const refreshToken = async (req, res) => {
  const { email, refreshToken } = req.body
  const isValid = verifyRefresh(email, refreshToken)
  if (!email) {
    return res.status(400).json({ success: false, error: 'Email is required' })
  }
  if (!isValid) {
    return res
      .status(401)
      .json({ success: false, error: 'Invalid token, try login again' })
  }
  const { accessToken } = jwtGeneration({ email })
  await res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: true,
    maxAge: 3600000,
  })
  return res.status(200).json({ success: true, accessToken })
}

export const logout = async (req, res) => {
  res.clearCookie('accessToken')
  return res.status(200).json({ success: true, message: 'Logout successfully' })
}
