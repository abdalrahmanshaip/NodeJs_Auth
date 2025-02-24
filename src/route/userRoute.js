import { Router } from 'express'
import {
  getUser,
  login,
  register,
  refreshToken,
  logout,
  forgotPass,
  resetPass,
  changePass
} from '../controller/userController.js'
import { verifyToken } from '../middleware/authMiddleware.js'
import { userValidation } from '../utils/authValidation.js'
const router = Router()

router.route('/register').post(userValidation(), register)
router.route('/login').post(login)
router.route('/refresh').post(refreshToken)
router.route('/logout').get(logout)
router.route('/forgot-pass').post(forgotPass)
router.route('/').get(verifyToken, getUser)

router.route('/reset/:token').post(resetPass)
router.route('/change-pass').post(verifyToken, changePass)

export default router
