const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const JWT_SECRET = 'TSDIIgP5';
const JWT_EXPIRATION = '1h';
const app = express()
require('dotenv').config();
app.use(express.json());
const cors = require('cors');
app.use(cors({
    origin: '*'
}))
const PORT = 5000
const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGO_URI
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("MongoDB connected")
}).catch((err) => {
    console.log("Error in connecting to MongoDB", err)
})

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
})
const noteSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: true
    },
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User"
    }
})
const User = new mongoose.model("User", userSchema)
const Note = new mongoose.model("Note", noteSchema)

app.post('/register', async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({ message: 'please provide username or password' })
    }
    const existingUser = await User.findOne({ username })
    if (existingUser) {
        return res.status(400).json({ message: "Username already exists" })
    }
    try {
        const hashedPasword = bcrypt.hashSync(password, 10)
        const newUser = new User({
            username,
            password: hashedPasword
        })
        await newUser.save()
        res.status(201).json({ message: `${username} saved successfully` })
    } catch (error) {
        res.status(500).json({ message: "Failed to save user" })
    }
})
app.post('/login', async (req, res) => {
    const { username, password } = req.body
    if (!username || !password) {
        return res.status(400).json({ message: 'please provide username or password' })
    }
    const user = await User.findOne({ username })
    if (!user) {
        return res.status(400).json({ message: "User not found" })
    }
    console.log(user)
    try {
        const isPasswordValid = bcrypt.compareSync(password, user.password)
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Password not matched" })
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRATION })
        console.log("Token generated: ", token)
        res.status(201).json({ token })
    } catch (error) {
        res.status(500).json({ message: "Failed to login" })
    }
})
const authenticate = async (req, res, next) => {
    console.log("Authentication middleware called")
    console.log("Headers: ", req.headers)
    const header = req.headers.authorization
    if (!header) {
        return res.status(401).json({ message: "No token provided" })
    }
    try {
        const decodedToken = jwt.verify(header.split(' ')[1], JWT_SECRET)

        req.userID = decodedToken.userId

        next()
    } catch (error) {
        res.status(401).json({ message: "Invalid token" })
    }
}
app.get("/notes", authenticate, async (req, res) => {
    console.log("Notes route")
    const notes = await Note.find({ userID: req.userID })
    console.log("Notes: ", notes)
    if (!notes) {
        return res.status(404).json({ message: "No notes found" })
    }
    res.status(200).json({ notes })
})
app.post("/notes", authenticate, async (req, res) => {
    console.log("Notes POST route")
    const { title, content } = req.body
    if (!title | !content) {
        return res.status(400).json({ message: "Please provide title and content" })
    }
    const newNote = {
        title, content, userID: req.userID
    }
    await new Note(newNote).save()
    res.status(201).json({ message: "Note saved successfully" })
})
app.delete("/notes/:id", authenticate, async (req, res) => {
    const id = req.params.id
    if (!id) {
        return res.status(400).json({ message: "Please provide note id" })
    }
    try {
        const noteToDelete = await Note.findById(id)
        if (!noteToDelete) {
            return res.status(404).json({ message: "Note not found" })
        }
        if (noteToDelete.userID.toString() !== req.userID) {
            return res.status(403).json({ message: "You are not authorized to delete this note" })
        }
        await Note.findByIdAndDelete(id)
        res.status(200).json({ message: "Note deleted successfully" })
    } catch (error) {
        res.status(500).json({ message: "Failed to delete note" })
    }
})
// app.get("*", (req, res) => {
//     res.status(200).send("Welcome to the Note App API");
// })
app.listen(PORT, () => {
    console.log(`App running on port ${PORT}`)
});