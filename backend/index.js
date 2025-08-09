// =================================================================
// 1. التحميل اليدوي لمتغيرات البيئة (الحل الجذري)
// =================================================================
const fs = require('fs');
const path = require('path');

try {
    const envConfig = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    envConfig.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            process.env[key.trim()] = value.trim();
        }
    });
    console.log('✅ Environment variables loaded manually.');
} catch (error) {
    console.error('Could not load .env file. Please ensure it exists in the backend folder.', error);
    process.exit(1); // إيقاف التشغيل إذا لم يتم العثور على الملف
}


// =================================================================
// 2. استدعاء المكتبات المطلوبة
// =================================================================
const http = require('http' );
const https = require('https' );
const { GoogleGenerativeAI } = require('@google/generative-ai');
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors'); // Import cors
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('./models/user.model.js');
const Chat = require('./models/chat.model.js');
const Settings = require('./models/settings.model.js');

// =================================================================
// 3. إعداد تطبيق Express والخادم
// =================================================================
const app = express();
const server = http.createServer(app);

// ✨ تحصين CORS للسماح بالتوكن والطلبات المعقدة ✨
const corsOptions = {
  origin: 'https://chatzeus.vercel.app',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'] // السماح بهيدر التوكن
};

app.use(cors(corsOptions ));
app.options('*', cors(corsOptions)); // الرد على طلبات pre-flight

const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    "https://chatzeus-production.up.railway.app/auth/google/callback" // <--- هذا هو الرابط الثابت والصحيح
 );

app.use(express.json({ limit: '50mb' }));


// =================================================================
// 4. Middleware للتحقق من التوكن
// =================================================================
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // استخراج التوكن من 'Bearer TOKEN'

    if (token == null) {
        return res.status(401).json({ loggedIn: false, message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ loggedIn: false, message: 'Token is not valid.' });
        }
        req.user = user;
        next();
    });
}


// =================================================================
// 5. نقاط النهاية (Routes)
// =================================================================
app.get('/auth/google', (req, res) => {
    const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
    } );
    res.redirect(authorizeUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    try {
        const { code } = req.query;
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const userInfoResponse = await oauth2Client.request({ url: 'https://www.googleapis.com/oauth2/v3/userinfo' } );
        const userInfo = userInfoResponse.data;

        // ابحث عن المستخدم في قاعدة البيانات أو أنشئ مستخدمًا جديدًا
        let user = await User.findOne({ googleId: userInfo.sub });

        if (!user) {
            // مستخدم جديد
            user = new User({
                googleId: userInfo.sub, // .sub هو المعرف الفريد من جوجل
                email: userInfo.email,
                name: userInfo.name,
                picture: userInfo.picture,
            });
            await user.save();

            // إنشاء إعدادات افتراضية للمستخدم الجديد
            const newSettings = new Settings({ user: user._id });
            await newSettings.save();
            console.log(`✨ New user created and saved: ${user.email}`);
        } else {
            console.log(`👋 Welcome back, user: ${user.email}`);
        }

        // إنشاء حمولة التوكن مع معرّف قاعدة البيانات
        const payload = {
            id: user._id, // ✨ الأهم: استخدام معرّف قاعدة البيانات
            name: user.name,
            email: user.email,
            picture: user.picture,
        };

        // توقيع التوكن
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

        // إعادة التوجيه إلى الواجهة الأمامية مع التوكن
        res.redirect(`https://chatzeus.vercel.app/?token=${token}` );

    } catch (error) {
        console.error('Authentication callback error:', error);
        res.redirect('https://chatzeus.vercel.app/?auth_error=true' );
    }
});

app.get('/api/user', verifyToken, (req, res) => {
    // إذا وصل الطلب إلى هنا، فالـ middleware قد تحقق من التوكن بنجاح
    // ومعلومات المستخدم موجودة في req.user
    res.json({ loggedIn: true, user: req.user });
});

app.post('/api/chat', verifyToken, async (req, res) => {
    await handleChatRequest(req, res);
});

// =================================================================
// ✨ نقاط نهاية جديدة للبيانات (تضاف في القسم 5)
// =================================================================

// جلب جميع بيانات المستخدم (المحادثات والإعدادات) - نسخة مضادة للرصاص
app.get('/api/data', verifyToken, async (req, res) => {
    try {
        // 1. تحقق من وجود المستخدم والـ ID في التوكن
        if (!req.user || !req.user.id) {
            console.error('Validation Error: User or User ID not found in token payload.');
            return res.status(401).json({ message: 'Invalid token: User ID missing.' });
        }
        const userIdString = req.user.id;
        console.log(`Attempting to fetch data for user ID: ${userIdString}`);

        // 2. ✨✨ الخطوة الجديدة والمهمة: تحقق من أن الـ ID صالح قبل محاولة التحويل ✨✨
        if (!mongoose.Types.ObjectId.isValid(userIdString)) {
            console.error(`Validation Error: Provided User ID "${userIdString}" is not a valid MongoDB ObjectId.`);
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        
        // 3. قم بالتحويل فقط بعد التأكد من صلاحيته
        const userIdObject = new mongoose.Types.ObjectId(userIdString);

        // 4. ابحث عن البيانات باستخدام الـ ID الصالح
        const chats = await Chat.find({ user: userIdObject }).sort({ order: -1 });
        let settings = await Settings.findOne({ user: userIdObject });

        // 5. إذا لم توجد إعدادات، أنشئها
        if (!settings) {
            console.log(`No settings found for user ${userIdObject}, creating new ones.`);
            settings = new Settings({ user: userIdObject });
            await settings.save();
        }

        console.log(`Successfully fetched data for user ${userIdObject}`);
        res.json({ chats, settings });

    } catch (error) {
        // 6. في حالة حدوث أي خطأ آخر، قم بتسجيله وإرساله
        console.error('FATAL: An unexpected error occurred while fetching user data:', error);
        res.status(500).json({ message: 'An internal server error occurred.', error: error.message });
    }
});

// حفظ أو تحديث محادثة
app.post('/api/chats', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const chatData = req.body;

        // إذا كان للمحادثة ID، قم بتحديثها. وإلا، أنشئ واحدة جديدة.
        if (chatData._id) {
            const updatedChat = await Chat.findByIdAndUpdate(
                chatData._id,
                { ...chatData, user: userId }, // تأكد من أن المستخدم هو المالك
                { new: true, runValidators: true }
            );
            res.json(updatedChat);
        } else {
            const newChat = new Chat({ ...chatData, user: userId });
            await newChat.save();
            res.status(201).json(newChat);
        }
    } catch (error) {
        console.error('Error saving chat:', error);
        res.status(500).json({ message: 'Failed to save chat' });
    }
});

// تحديث الإعدادات
app.put('/api/settings', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const settingsData = req.body;

        const updatedSettings = await Settings.findOneAndUpdate(
            { user: userId },
            settingsData,
            { new: true, upsert: true } // upsert: إذا لم تكن موجودة، أنشئها
        );
        res.json(updatedSettings);
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ message: 'Failed to update settings' });
    }
});

// حذف محادثة
app.delete('/api/chats/:chatId', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { chatId } = req.params;

        const result = await Chat.findOneAndDelete({ _id: chatId, user: userId });

        if (!result) {
            return res.status(404).json({ message: 'Chat not found or user not authorized' });
        }

        res.status(200).json({ message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Error deleting chat:', error);
        res.status(500).json({ message: 'Failed to delete chat' });
    }
});

// =================================================================
// 5. عرض الملفات الثابتة
// =================================================================
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// مسار للصفحة الرئيسية فقط (بدلاً من * التي تسبب تضارب)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});


// =================================================================
// 6. دوال معالجة الدردشة (تبقى كما هي)
// =================================================================
const keyManager = {
    keys: {
        gemini: (process.env.GEMINI_API_KEYS || '').split(',').filter(k => k),
        openrouter: (process.env.OPENROUTER_API_KEYS || '').split(',').filter(k => k)
    },
    indices: { gemini: 0, openrouter: 0 },
    tryKeys: async function(provider, strategy, customKeys, action) {
        const keyPool = customKeys.length > 0 ? customKeys : this.keys[provider] || [];
        if (keyPool.length === 0) throw new Error(`لا توجد مفاتيح API للمزود ${provider}`);
        for (let i = 0; i < keyPool.length; i++) {
            const key = keyPool[i];
            try { return await action(key); } catch (error) {
                console.error(`[Key Manager] فشل المفتاح ${i + 1} للمزود ${provider}:`, error.message);
                if (i === keyPool.length - 1) throw new Error(`فشلت جميع مفاتيح API للمزود ${provider}.`);
            }
        }
    }
};
async function handleChatRequest(req, res) {
    try {
        const payload = req.body;
        // ✨ التحقق من وجود الإعدادات والمزود قبل أي شيء آخر ✨
        if (!payload.settings || !payload.settings.provider) {
            // إذا لم يكن هناك مزود، أرسل خطأ واضحًا بدلاً من الانهيار
            throw new Error('Provider information is missing in the request settings.');
        }
        const { provider } = payload.settings;

        // الآن يمكننا استخدام 'provider' بأمان
        if (provider === 'gemini') await handleGeminiRequest(payload, res);
        else if (provider === 'openrouter') await handleOpenRouterRequest(payload, res);
        else if (provider.startsWith('custom_')) await handleCustomProviderRequest(payload, res);
        else throw new Error(`مزود غير معروف: ${provider}`);
        
    } catch (error) {
        console.error('Error processing chat request:', error.message);
        res.status(500).json({ error: error.message });
    }
}
async function handleGeminiRequest(payload, res) {
    const { chatHistory, attachments, settings } = payload;
    await keyManager.tryKeys('gemini', settings.apiKeyRetryStrategy, [], async (apiKey) => {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: settings.model });
        const history = chatHistory.slice(0, -1).map(msg => ({ role: msg.role === 'user' ? 'user' : 'model', parts: [{ text: msg.content || '' }] }));
        const lastMessage = chatHistory[chatHistory.length - 1];
        const userParts = buildUserParts(lastMessage, attachments);
        const chat = model.startChat({ history, generationConfig: { temperature: settings.temperature } });
        const result = await chat.sendMessageStream(userParts);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Transfer-Encoding': 'chunked' });
        for await (const chunk of result.stream) { res.write(chunk.text()); }
        res.end();
    });
}
async function handleOpenRouterRequest(payload, res) {
    const { chatHistory, settings } = payload;
    await keyManager.tryKeys('openrouter', settings.apiKeyRetryStrategy, [], async (apiKey) => {
        const formattedMessages = formatMessagesForOpenAI(chatHistory);
        const requestBody = JSON.stringify({ model: settings.model, messages: formattedMessages, temperature: settings.temperature, stream: true });
        const options = { hostname: 'openrouter.ai', path: '/api/v1/chat/completions', method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' } };
        await streamOpenAICompatibleAPI(options, requestBody, res);
    });
}
async function handleCustomProviderRequest(payload, res) {
    const { chatHistory, settings, customProviders } = payload;
    const providerId = settings.provider;
    const providerConfig = customProviders.find(p => p.id === providerId);
    if (!providerConfig) throw new Error(`لم يتم العثور على إعدادات المزود المخصص: ${providerId}`);
    const customKeys = (providerConfig.apiKeys || []).map(k => k.key).filter(Boolean);
    await keyManager.tryKeys(providerId, settings.apiKeyRetryStrategy, customKeys, async (apiKey) => {
        const formattedMessages = formatMessagesForOpenAI(chatHistory);
        const requestBody = JSON.stringify({ model: settings.model, messages: formattedMessages, temperature: settings.temperature, stream: true });
        const url = new URL(providerConfig.baseUrl);
        const options = { hostname: url.hostname, path: url.pathname, method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' } };
        await streamOpenAICompatibleAPI(options, requestBody, res);
    });
}
function buildUserParts(lastMessage, attachments) {
    const userParts = [];
    if (lastMessage.content) userParts.push({ text: lastMessage.content });
    if (attachments) {
        attachments.forEach(file => {
            if (file.dataType === 'image' && file.content) {
                userParts.push({ inline_data: { mime_type: file.mimeType, data: file.content } });
            } else if (file.dataType === 'text' && file.content) {
                userParts.push({ text: `\n\n--- محتوى الملف: ${file.name} ---\n${file.content}\n--- نهاية الملف ---` });
            }
        });
    }
    if (userParts.length > 0 && userParts.every(p => !p.text)) {
        userParts.unshift({ text: "حلل المرفقات:" });
    }
    return userParts;
}
function formatMessagesForOpenAI(chatHistory) {
    return chatHistory.map(msg => ({ role: msg.role, content: msg.content || '' }));
}
function streamOpenAICompatibleAPI(options, body, res) {
    return new Promise((resolve, reject) => {
        const request = https.request(options, (apiResponse ) => {
            if (apiResponse.statusCode !== 200) {
                let errorBody = '';
                apiResponse.on('data', d => errorBody += d);
                apiResponse.on('end', () => reject(new Error(`API Error: ${apiResponse.statusCode} - ${errorBody}`)));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Transfer-Encoding': 'chunked' });
            apiResponse.on('data', (chunk) => {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6);
                        if (data.trim() === '[DONE]') continue;
                        try {
                            const parsed = JSON.parse(data);
                            const text = parsed.choices?.[0]?.delta?.content || '';
                            if (text) res.write(text);
                        } catch (e) {}
                    }
                }
            });
            apiResponse.on('end', () => { res.end(); resolve(); });
        });
        request.on('error', reject);
        request.write(body);
        request.end();
    });
}

// =================================================================
// ✨ الاتصال بقاعدة البيانات
// =================================================================
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB Atlas.'))
    .catch(err => {
        console.error('❌ Could not connect to MongoDB Atlas.', err);
        process.exit(1); // إيقاف الخادم إذا فشل الاتصال
    });

// =================================================================
// 7. تشغيل الخادم
// =================================================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Zeus Pro Server (Manual Env) is now running on http://0.0.0.0:${PORT}` );
});
