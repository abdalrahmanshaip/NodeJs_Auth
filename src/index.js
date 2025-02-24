import express from 'express'
import userRoute from './route/userRoute.js'
import connectDB from './config/db.js'
import cookieParser from 'cookie-parser'

const port = process.env.PORT

const app = express()
connectDB()

app.use(express.json())
app.use(cookieParser())

app.use('/api/users', userRoute)

app.listen(port, () => {
  console.log(`Server listening on port ${port}`)
})
