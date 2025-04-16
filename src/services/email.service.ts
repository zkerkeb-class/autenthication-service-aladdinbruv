import nodemailer from 'nodemailer';
import config from '../config';

class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.auth.user,
        pass: config.email.auth.pass,
      },
    });
  }

  /**
   * Send an email
   */
  async sendEmail(to: string, subject: string, html: string): Promise<void> {
    const mailOptions = {
      from: config.email.from,
      to,
      subject,
      html,
    };

    await this.transporter.sendMail(mailOptions);
  }

  /**
   * Send verification email
   */
  async sendVerificationEmail(to: string, verificationLink: string): Promise<void> {
    const subject = 'Verify your email for SK8 App';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to SK8 App!</h2>
        <p>Thank you for signing up. Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationLink}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
            Verify Email
          </a>
        </div>
        <p>If the button doesn't work, you can also copy and paste the following link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationLink}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't sign up for SK8 App, you can safely ignore this email.</p>
        <p>Best regards,<br>The SK8 App Team</p>
      </div>
    `;

    await this.sendEmail(to, subject, html);
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(to: string, resetLink: string): Promise<void> {
    const subject = 'Reset your password for SK8 App';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Reset Your Password</h2>
        <p>We received a request to reset your password for your SK8 App account. Click the button below to set a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
            Reset Password
          </a>
        </div>
        <p>If the button doesn't work, you can also copy and paste the following link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${resetLink}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, you can safely ignore this email.</p>
        <p>Best regards,<br>The SK8 App Team</p>
      </div>
    `;

    await this.sendEmail(to, subject, html);
  }

  /**
   * Send welcome email after registration
   */
  async sendWelcomeEmail(to: string, name: string): Promise<void> {
    const subject = 'Welcome to SK8 App!';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to SK8 App, ${name}!</h2>
        <p>Thank you for joining SK8 App. We're excited to have you as part of our community.</p>
        <p>With SK8 App, you can:</p>
        <ul>
          <li>Track your skateboarding progress</li>
          <li>Connect with other skaters</li>
          <li>Discover new skateparks and spots</li>
          <li>Share your tricks and achievements</li>
        </ul>
        <p>If you have any questions or need assistance, feel free to contact our support team.</p>
        <p>Best regards,<br>The SK8 App Team</p>
      </div>
    `;

    await this.sendEmail(to, subject, html);
  }
}

export default new EmailService(); 