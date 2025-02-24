import { body } from 'express-validator'

export const userValidation = () => {
  return [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 1 }).withMessage('Password is required'),
  ]
}
