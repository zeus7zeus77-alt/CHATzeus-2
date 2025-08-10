const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    role: { type: String, enum: ['user', 'assistant'], required: true },
    content: { type: String, required: true },
    attachments: [{
        name: String,
        size: Number,
        type: String
    }],
    timestamp: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, default: 'محادثة جديدة' },
    messages: [messageSchema],
    order: { type: Number, default: () => Date.now() }
}, { timestamps: true });

const Chat = mongoose.model('Chat', chatSchema);

module.exports = Chat;
