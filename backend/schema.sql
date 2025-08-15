-- NetSage Database Schema for NeonDB

-- Table: scan_requests
-- Purpose: Stores scan requests from frontend
CREATE TABLE scan_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  website_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table: raw_scan_data
-- Purpose: Stores raw JSON data from n8n
CREATE TABLE raw_scan_data (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id UUID NOT NULL REFERENCES scan_requests(id),
  raw_json JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table: scan_results
-- Purpose: Stores cleaned and processed scan results
CREATE TABLE scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id UUID NOT NULL REFERENCES scan_requests(id),
  target TEXT,
  port INTEGER,
  service TEXT,
  product TEXT,
  version TEXT,
  report TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster lookups by request_id
CREATE INDEX idx_raw_scan_data_request_id ON raw_scan_data(request_id);
CREATE INDEX idx_scan_results_request_id ON scan_results(request_id);

-- Comment explaining usage
COMMENT ON TABLE scan_requests IS 'Stores website scan requests from frontend with their current status';
COMMENT ON TABLE raw_scan_data IS 'Stores the raw JSON data received from n8n workflow';
COMMENT ON TABLE scan_results IS 'Stores the cleaned and processed scan results with generated security report';

-- Add new columns to scan_results for additional data
ALTER TABLE scan_results ADD COLUMN http_security JSONB;
ALTER TABLE scan_results ADD COLUMN vulnerabilities JSONB;
ALTER TABLE scan_results ADD COLUMN vulnerability_summary JSONB;
ALTER TABLE scan_results ADD COLUMN scan_metadata JSONB;
ALTER TABLE scan_results ADD COLUMN scan_timestamp TIMESTAMP;
ALTER TABLE scan_results ADD COLUMN scan_duration INTEGER;

-- Add new columns to scan_results table for additional data fields
-- Run this script if you haven't already added these columns

-- Check if columns already exist and add them if they don't
DO $$
BEGIN
    -- Add protocol column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='scan_results' AND column_name='protocol') THEN
        ALTER TABLE scan_results ADD COLUMN protocol TEXT;
    END IF;

    -- Add state column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='scan_results' AND column_name='state') THEN
        ALTER TABLE scan_results ADD COLUMN state TEXT;
    END IF;

    -- Add banner column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='scan_results' AND column_name='banner') THEN
        ALTER TABLE scan_results ADD COLUMN banner TEXT;
    END IF;
END $$;

-- Add comments explaining these new columns
COMMENT ON COLUMN scan_results.protocol IS 'Network protocol (tcp, udp, etc.)';
COMMENT ON COLUMN scan_results.state IS 'Port state (open, closed, filtered)';
COMMENT ON COLUMN scan_results.banner IS 'Service banner information if available';
