const mongoose = require('mongoose');

/**
 * Connect to MongoDB database
 * Updated for newer Mongoose versions
 */
async function connectDB() {
  try {
    const options = {
      // Connection pool settings
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      
      // Removed deprecated options:
      // bufferMaxEntries: 0, // ❌ Deprecated
      // authSource: 'admin', // ❌ Not needed for local MongoDB
      
      // Keep these working options:
      retryWrites: true
    };

    // Get MongoDB URI from environment or use default
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/privacy-data-vault';

    console.log('🔄 Connecting to MongoDB...');
    
    const conn = await mongoose.connect(mongoURI, options);

    // Connection event listeners
    mongoose.connection.on('connected', () => {
      console.log('✅ MongoDB connected successfully');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('📡 MongoDB disconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('✅ MongoDB connection closed through app termination');
        process.exit(0);
      } catch (err) {
        console.error('❌ Error closing MongoDB connection:', err);
        process.exit(1);
      }
    });

    return conn;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    
    // Show helpful error messages
    if (error.message.includes('ECONNREFUSED')) {
      console.log('💡 MongoDB is not running. Install and start MongoDB:');
      console.log('   1. Download from: https://www.mongodb.com/try/download/community');
      console.log('   2. Or use Docker: docker run -d -p 27017:27017 mongo');
      console.log('   3. Or comment out database connection in server.js to run without DB');
    }
    
    throw error;
  }
}

/**
 * Close database connection
 */
async function closeDB() {
  try {
    await mongoose.connection.close();
    console.log('📴 Database connection closed');
  } catch (error) {
    console.error('❌ Error closing database:', error);
    throw error;
  }
}

/**
 * Clear all collections (for testing)
 */
async function clearDB() {
  try {
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      const collection = collections[key];
      await collection.deleteMany({});
    }
    console.log('🗑️ Database cleared');
  } catch (error) {
    console.error('❌ Error clearing database:', error);
    throw error;
  }
}

module.exports = {
  connectDB,
  closeDB,
  clearDB
};

// Also export as default for backward compatibility
module.exports.default = connectDB;
