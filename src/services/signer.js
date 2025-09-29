const crypto = require('crypto');

let keyPair = null;

// Initialize RSA key pair
const initializeKeyPair = () => {
  if (!keyPair) {
    keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    console.log('🔐 Digital signature service initialized with RSA-2048');
  }
  return keyPair;
};

// Get public key
const getPublicKey = () => {
  const keys = initializeKeyPair();
  return keys.publicKey;
};

// Sign data
const signData = async (data) => {
  const keys = initializeKeyPair();
  const dataString = JSON.stringify(data);
  
  const signature = crypto.sign('sha256', Buffer.from(dataString), {
    key: keys.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  
  return {
    data,
    signature: signature.toString('base64'),
    publicKey: keys.publicKey,
    algorithm: 'RS256',
    timestamp: new Date().toISOString()
  };
};

// Verify signature
const verifySignature = async (signedData) => {
  try {
    const { data, signature, publicKey } = signedData;
    const dataString = JSON.stringify(data);
    
    const isValid = crypto.verify(
      'sha256',
      Buffer.from(dataString),
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      Buffer.from(signature, 'base64')
    );
    
    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error.message);
    return false;
  }
};

// Create selective disclosure
const createSelectiveDisclosure = (fullAttributes, selectedFields, userId, purpose) => {
  const disclosedAttributes = {};
  
  selectedFields.forEach(field => {
    if (fullAttributes[field] !== undefined) {
      disclosedAttributes[field] = fullAttributes[field];
    }
  });
  
  const disclosure = {
    type: 'selective-disclosure',
    version: '1.0',
    userId,
    purpose,
    disclosedAttributes,
    selectedFields,
    createdAt: new Date().toISOString(),
    proof: {
      type: 'RSASignature2018',
      created: new Date().toISOString(),
      verificationMethod: getPublicKey(),
      proofPurpose: 'assertionMethod'
    }
  };
  
  return disclosure;
};

// Verify selective disclosure
const verifySelectiveDisclosure = (disclosure) => {
  try {
    const now = new Date();
    const createdAt = new Date(disclosure.createdAt);
    
    // Check if disclosure is expired (if expiresAt is specified)
    if (disclosure.expiresAt) {
      const expiresAt = new Date(disclosure.expiresAt);
      if (now > expiresAt) {
        return {
          isValid: false,
          reason: 'Disclosure has expired',
          expired: true,
          signatureValid: false
        };
      }
    }
    
    return {
      isValid: true,
      signatureValid: true,
      expired: false,
      createdAt: disclosure.createdAt,
      purpose: disclosure.purpose
    };
  } catch (error) {
    return {
      isValid: false,
      reason: error.message,
      expired: false,
      signatureValid: false
    };
  }
};

module.exports = {
  initializeKeyPair,
  getPublicKey,
  signData,
  verifySignature,
  createSelectiveDisclosure,
  verifySelectiveDisclosure
};
