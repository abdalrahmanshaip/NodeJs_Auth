import mongoose from 'mongoose'
import dotenv from 'dotenv'
dotenv.config()

const URL = process.env.MONGO_URL
const connectDB = async () => {
  try {
    await mongoose.connect(URL)
    console.log('MongoDB connected')
  } catch (error) {
    console.error('MongoDB connection failed:', error)
    process.exit(1)
  }
}
export default connectDB
