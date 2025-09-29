require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');

// Import configurations
const { connectDB } = require('./src/config/database');
// Import routes
const authRoutes = require('./src/routes/auth');
const vaultRoutes = require('./src/routes/vault');
const adminRoutes = require('./src/routes/admin');

// Import middleware
const { globalErrorHandler } = require('./src/middleware/errorHandler');
const rateLimiter = require('./src/middleware/rateLimiter');

const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src/views'));

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Logging middleware
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/public', express.static(path.join(__dirname, 'public')));

// Rate limiting
app.use(rateLimiter.general);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Add this after the health check endpoint and before your existing routes
app.get('/api', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Privacy-First Data Vault API is running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth',
      vault: '/api/vault', 
      admin: '/api/admin',
      health: '/health'
    }
  });
});

// Your existing routes (keep these as they are)
app.use('/api/auth', authRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/admin', adminRoutes);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/admin', adminRoutes);

// Frontend routes
app.get('/', (req, res) => {
  res.render('signup', { 
    title: 'Privacy-First Data Vault - Sign Up',
    error: null 
  });
});

app.get('/login', (req, res) => {
  res.render('login', { 
    title: 'Privacy-First Data Vault - Login',
    error: null 
  });
});

app.get('/dashboard', (req, res) => {
  res.render('dashboard', { 
    title: 'Privacy-First Data Vault - Dashboard',
    user: null 
  });
});

app.get('/share', (req, res) => {
  res.render('share', { 
    title: 'Privacy-First Data Vault - Share Data',
    user: null 
  });
});

app.get('/admin', (req, res) => {
  res.render('admin', { 
    title: 'Privacy-First Data Vault - Admin Panel',
    user: null 
  });
});

// 404 handler - must be before global error handler
app.all('*', (req, res, next) => {
  const { AppError } = require('./src/middleware/errorHandler');
  const err = new AppError(`Can't find ${req.originalUrl} on this server!`, 404);
  next(err);
});


// Global error handler
app.use(globalErrorHandler);

// Connect to database and start server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

async function startServer() {
  try {
    // Connect to MongoDB
    if (process.env.NODE_ENV !== 'test') {
      await connectDB();
      console.log('✅ Database connected successfully');
    }

    // Start server
    const server = app.listen(PORT, HOST, () => {
      console.log(`🚀 Server running on http://${HOST}:${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📧 Email service: ${process.env.EMAIL_SERVICE || 'Not configured'}`);
    });

    // Graceful shutdown
    const gracefulShutdown = (signal) => {
      console.log(`\n📴 Received ${signal}. Starting graceful shutdown...`);
      server.close((err) => {
        if (err) {
          console.error('❌ Error during server shutdown:', err);
          process.exit(1);
        }
        console.log('✅ Server closed successfully');
        process.exit(0);
      });
    };

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);

    return server;
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Start server if this file is run directly
if (require.main === module) {
  startServer();
}

module.exports = app;