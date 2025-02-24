import { Router } from 'express'
import { getUser, login, register } from '../controller/userController.js'
import { verifyToken } from '../middleware/authMiddleware.js'
import { userValidation } from '../utils/authValidation.js'
const router = Router()

router.route('/').get(verifyToken, getUser)
router.route('/register').post(userValidation(), register)
router.route('/login').post(login)

router.route('/:id').get().put().delete()

export default router
