/**
 * Knowledge Base of Target Brands for Impersonation Detection
 * Covers Global & Regional Financial, Tech, Government, Recruitment, and E-commerce entities.
 */

const TARGET_BRANDS = [
  // Global & Regional Banking / Financial
  {
    id: 'chase',
    name: 'JPMorgan Chase',
    category: 'banking',
    primaryDomains: ['chase.com', 'jpmorganchase.com', 'jpmorgan.com'],
    keywords: ['chase', 'jpmorgan', 'chase bank', 'chase online'],
    lures: ['urgent account verification', 'unauthorized transaction', 'suspicious wire', 'card locked']
  },
  {
    id: 'paypal',
    name: 'PayPal',
    category: 'fintech',
    primaryDomains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal', 'paypal credit', 'paypal resolution'],
    lures: ['unusual login activity', 'account limited', 'confirm payment', 'invoice cancelled']
  },
  {
    id: 'sbi',
    name: 'State Bank of India',
    category: 'banking',
    primaryDomains: ['onlinesbi.sbi', 'sbi.co.in'],
    keywords: ['onlinesbi', 'state bank of india', 'sbi card', 'yono sbi', 'sbi yono'],
    lures: ['kyc update required', 'pan card linking', 'yono reward points', 'debit card blocked']
  },
  {
    id: 'hdfc',
    name: 'HDFC Bank',
    category: 'banking',
    primaryDomains: ['hdfcbank.com', 'hdfc.com'],
    keywords: ['hdfc', 'hdfc bank', 'netbanking hdfc'],
    lures: ['netbanking password expiry', 'kyc re-verification', 'credit card reward redemption']
  },
  {
    id: 'wellsfargo',
    name: 'Wells Fargo',
    category: 'banking',
    primaryDomains: ['wellsfargo.com'],
    keywords: ['wells fargo', 'wellsfargo'],
    lures: ['fraud alert', 'verify account access', 'wire transfer pending']
  },
  {
    id: 'bankofamerica',
    name: 'Bank of America',
    category: 'banking',
    primaryDomains: ['bankofamerica.com', 'bofa.com'],
    keywords: ['bank of america', 'bofa', 'merrill lynch'],
    lures: ['safepass verification', 'security confirmation', 'temporary account hold']
  },

  // Tech Giants & Cloud Identity
  {
    id: 'google',
    name: 'Google & Workspace',
    category: 'technology',
    primaryDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'drive.google.com'],
    keywords: ['google', 'gmail', 'google drive', 'google account', 'google workspace'],
    lures: ['shared document on google drive', 'storage quota exceeded', 'security alert for account']
  },
  {
    id: 'microsoft',
    name: 'Microsoft 365 & Azure',
    category: 'technology',
    primaryDomains: ['microsoft.com', 'login.microsoftonline.com', 'live.com', 'office.com'],
    keywords: ['microsoft', 'office 365', 'outlook', 'azure', 'sharepoint', 'onedrive'],
    lures: ['voice message received', 'sharepoint document encrypted', 'password expires today', 'mfa reset']
  },
  {
    id: 'apple',
    name: 'Apple iCloud',
    category: 'technology',
    primaryDomains: ['apple.com', 'icloud.com'],
    keywords: ['apple', 'apple id', 'icloud', 'find my iphone'],
    lures: ['apple id locked for security', 'iphone found nearby', 'receipt for unauthorized purchase']
  },
  {
    id: 'netflix',
    name: 'Netflix',
    category: 'entertainment',
    primaryDomains: ['netflix.com'],
    keywords: ['netflix', 'netflix billing'],
    lures: ['membership suspended', 'payment declined', 'update payment method to continue watching']
  },

  // Recruitment, HR & Freelance Portals
  {
    id: 'linkedin',
    name: 'LinkedIn Jobs',
    category: 'recruitment',
    primaryDomains: ['linkedin.com'],
    keywords: ['linkedin', 'linkedin recruiter', 'linkedin learning'],
    lures: ['you have been selected for interview', 'new job match offer', 'hr requested contact']
  },
  {
    id: 'workday',
    name: 'Workday Portal',
    category: 'recruitment',
    primaryDomains: ['workday.com', 'myworkdayjobs.com'],
    keywords: ['workday', 'myworkday', 'workday application'],
    lures: ['submit background verification document', 'offer letter acceptance', 'tax declaration']
  },
  {
    id: 'naukri',
    name: 'Naukri.com / Job Portals',
    category: 'recruitment',
    primaryDomains: ['naukri.com', 'naukrigulf.com', 'indeed.com'],
    keywords: ['naukri', 'indeed', 'fastforward resume'],
    lures: ['direct interview call letter', 'hr screening deposit', 'work from home job confirmation']
  },

  // Government & Public Infrastructure Services
  {
    id: 'irctc',
    name: 'Indian Railways (IRCTC)',
    category: 'government',
    primaryDomains: ['irctc.co.in'],
    keywords: ['irctc', 'indian railways', 'cris ticketing'],
    lures: ['ticket cancellation refund processing', 'verify aadhaar for tatkal', 'mobile ticket update']
  },
  {
    id: 'incometax',
    name: 'Income Tax Department / IRS',
    category: 'government',
    primaryDomains: ['incometax.gov.in', 'irs.gov'],
    keywords: ['income tax', 'efiling income tax', 'irs refund', 'tax rebate'],
    lures: ['urgent tax refund pending approval', 'notice of penalty under section', 'claim tax credit']
  },
  {
    id: 'usps',
    name: 'US Postal Service / Logistics',
    category: 'logistics',
    primaryDomains: ['usps.com', 'fedex.com', 'dhl.com'],
    keywords: ['usps', 'fedex', 'dhl express', 'postal delivery'],
    lures: ['package address incomplete', 'customs fee unpaid', 'redelivery reschedule required']
  },

  // Crypto / Digital Assets
  {
    id: 'binance',
    name: 'Binance Exchange',
    category: 'crypto',
    primaryDomains: ['binance.com'],
    keywords: ['binance', 'binance chain', 'trust wallet'],
    lures: ['withdrawal approved', 'account liquidation warning', 'airdrop claim']
  },
  {
    id: 'metamask',
    name: 'MetaMask Web3 Wallet',
    category: 'crypto',
    primaryDomains: ['metamask.io'],
    keywords: ['metamask', 'seed phrase', 'ethereum wallet'],
    lures: ['verify 12-word recovery phrase', 'sync hardware wallet', 'upgrade security contract']
  }
];

// Suspicious Keywords often stuffed in malicious URLs
const SUSPICIOUS_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'secure', 'security', 'account', 'verify',
  'verification', 'update', 'banking', 'wallet', 'confirm', 'validation', 'authenticate',
  'recover', 'recovery', 'passcode', 'credential', 'suspension', 'reactivate', 'claim',
  'refund', 'kyc', 'aadhaar', 'pan', 'invoice', 'document', 'e-vault', 'payment-gateway',
  'billing', 'support', 'helpdesk', 'resolution', 'dispute', 'urgent', 'portal-login'
];

// High-risk generic Top Level Domains (TLDs) frequently abused in fast-flux phishing campaigns
const HIGH_RISK_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.cam', '.work',
  '.click', '.rest', '.icu', '.monster', '.support', '.download', '.racing', '.loan',
  '.sbs', '.cfd', '.quest', '.beauty', '.stream', '.date'
];

module.exports = {
  TARGET_BRANDS,
  SUSPICIOUS_URL_KEYWORDS,
  HIGH_RISK_TLDS
};
