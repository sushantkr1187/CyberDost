CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Audited X.509 Certificates & Cryptographic Telemetry
CREATE TABLE audited_certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sha256_fingerprint VARCHAR(64) UNIQUE NOT NULL,
    serial_hex VARCHAR(128) NOT NULL,
    subject_cn VARCHAR(255),
    issuer_cn VARCHAR(255) NOT NULL,
    key_algorithm VARCHAR(64) NOT NULL,
    entropy_bits NUMERIC(6, 2),
    is_compromised_ca BOOLEAN DEFAULT FALSE,
    small_scalar_vulnerable BOOLEAN DEFAULT FALSE,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Full URL Scan History
CREATE TABLE url_scan_reports (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_url TEXT NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    composite_risk_score SMALLINT NOT NULL CHECK (composite_risk_score BETWEEN 0 AND 100),
    verdict VARCHAR(32) NOT NULL,
    pki_risk_score SMALLINT NOT NULL,
    domain_risk_score SMALLINT NOT NULL,
    sandbox_risk_score SMALLINT NOT NULL,
    posture_risk_score SMALLINT NOT NULL,
    impersonated_brand VARCHAR(255),
    visual_phash VARCHAR(32),
    cert_fingerprint VARCHAR(64) REFERENCES audited_certificates(sha256_fingerprint),
    raw_stix_bundle JSONB NOT NULL,
    scanned_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Collaborative Threat Intelligence IOCs
CREATE TABLE community_iocs (
    ioc_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator TEXT UNIQUE NOT NULL,
    threat_type VARCHAR(128) NOT NULL,
    issuer_ca VARCHAR(255),
    confidence SMALLINT NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    upvotes INTEGER NOT NULL DEFAULT 1,
    downvotes INTEGER NOT NULL DEFAULT 0,
    submitted_by VARCHAR(128) DEFAULT 'anonymous-soc',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scan_hostname ON url_scan_reports(hostname);
CREATE INDEX idx_cert_serial ON audited_certificates(serial_hex);
