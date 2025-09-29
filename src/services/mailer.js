// src/services/mailer.js
require('dotenv').config();
const nodemailer = require('nodemailer');

/*-------------------------------------------------------
  1.  Create transporter with your email config
-------------------------------------------------------*/
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,           // gmail
  host: process.env.EMAIL_HOST,                 // smtp.gmail.com
  port: +process.env.EMAIL_PORT,                // 587
  secure: false,                                // false for port 587
  auth: {
    user: process.env.EMAIL_USER,               // smartwill660@gmail.com
    pass: process.env.EMAIL_PASS                // gxee pnvi hgze zssd
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

/*-------------------------------------------------------
  2.  Verify connection at startup
-------------------------------------------------------*/
(async () => {
  try {
    await transporter.verify();
    console.log('✅ Email service ready (Gmail SMTP)');
  } catch (err) {
    console.error('❌ Failed to initialize email service:', err.message);
  }
})();

/*-------------------------------------------------------
  3.  Email sending functions
-------------------------------------------------------*/
function sendMail({ to, subject, html, text }) {
  return transporter.sendMail({
    from: process.env.EMAIL_FROM,                // Privacy Vault <smartwill660@gmail.com>
    to,
    subject,
    text: text || html?.replace(/<[^>]+>/g, ''), // fallback to plain text
    html
  });
}

// Send email verification
exports.sendVerificationEmail = (to, username, verificationUrl) =>
  sendMail({
    to,
    subject: '🔐 Verify your Privacy Vault account',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #667eea;">Welcome to Privacy Vault!</h2>
        <p>Hi <strong>${username}</strong>,</p>
        <p>Thank you for creating your Privacy Vault account. Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 15px 30px; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    display: inline-block;">
            Verify Email Address
          </a>
        </div>
        <p>Or copy and paste this link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
        <p><small>This link expires in 24 hours. If you didn't create this account, please ignore this email.</small></p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #888; font-size: 12px;">Privacy Vault - Your data, your control</p>
      </div>
    `
  });

// Send 2FA OTP
exports.sendOTPEmail = (to, username, otp) =>
  sendMail({
    to,
    subject: '🔢 Your Privacy Vault verification code',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #667eea;">Two-Factor Authentication</h2>
        <p>Hi <strong>${username}</strong>,</p>
        <p>Your verification code for Privacy Vault login is:</p>
        <div style="text-align: center; margin: 30px 0;">
          <div style="display: inline-block; 
                      background: #f8f9fa; 
                      border: 2px dashed #667eea; 
                      padding: 20px 30px; 
                      border-radius: 15px;">
            <span style="font-size: 32px; 
                         font-weight: bold; 
                         color: #667eea; 
                         letter-spacing: 5px;">
              ${otp}
            </span>
          </div>
        </div>
        <p><strong>This code expires in 5 minutes.</strong></p>
        <p><small>If you didn't request this code, please ignore this email and secure your account.</small></p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #888; font-size: 12px;">Privacy Vault - Your data, your control</p>
      </div>
    `
  });

// Send password reset
exports.sendPasswordResetEmail = (to, username, resetUrl) =>
  sendMail({
    to,
    subject: '🔑 Reset your Privacy Vault password',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #667eea;">Password Reset Request</h2>
        <p>Hi <strong>${username}</strong>,</p>
        <p>We received a request to reset your Privacy Vault password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
                    color: white; 
                    padding: 15px 30px; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>Or copy and paste this link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${resetUrl}</p>
        <p><strong>This link expires in 1 hour.</strong></p>
        <p><small>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</small></p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #888; font-size: 12px;">Privacy Vault - Your data, your control</p>
      </div>
    `
  });

// Send welcome email after successful registration
exports.sendWelcomeEmail = (to, username) =>
  sendMail({
    to,
    subject: '🎉 Welcome to Privacy Vault!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #667eea;">Account Verified Successfully!</h2>
        <p>Hi <strong>${username}</strong>,</p>
        <p>Congratulations! Your Privacy Vault account has been verified and is now active.</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <h3 style="color: #333; margin-top: 0;">What's Next?</h3>
          <ul style="color: #666;">
            <li>📝 Add your personal data to your encrypted vault</li>
            <li>🔐 Set up two-factor authentication for extra security</li>
            <li>📤 Create selective disclosures to share specific data</li>
            <li>🔍 Monitor access to your data through audit logs</li>
          </ul>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.CLIENT_URL || 'http://localhost:3000'}/dashboard" 
             style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 15px 30px; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    display: inline-block;">
            Access Your Vault
          </a>
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #888; font-size: 12px;">Privacy Vault - Your data, your control</p>
      </div>
    `
  });

module.exports = {
  sendVerificationEmail: exports.sendVerificationEmail,
  sendOTPEmail: exports.sendOTPEmail,
  sendPasswordResetEmail: exports.sendPasswordResetEmail,
  sendWelcomeEmail: exports.sendWelcomeEmail
};
