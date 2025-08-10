const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    role: { type: String, required: true, enum: ['user', 'assistant'] },
    // ✨✨✨ الإصلاح هنا: زيادة الحد الأقصى لطول المحتوى ✨✨✨
    content: { type: String, maxLength: 400000 }, // زيادة الحد إلى 200 ألف حرف
    attachments: [{
        name: String,
        size: Number,
        type: String
    }],
    timestamp: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true, default: 'محادثة جديدة' },
    messages: [messageSchema],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    order: { type: Number, default: () => Date.now() }
}, { timestamps: true });

// إضافة فهرس لضمان سرعة البحث
chatSchema.index({ user: 1, updatedAt: -1 });

const Chat = mongoose.model('Chat', chatSchema);
module.exports = Chat;
