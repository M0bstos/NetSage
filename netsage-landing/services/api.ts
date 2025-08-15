/**
 * API Service for NetSage Backend
 * 
 * This service handles all HTTP requests to the backend API.
 */

// Define the base URL for the API - using Next.js environment variables
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  [key: string]: any;
}

export interface ScanRequestResponse extends ApiResponse {
  requestId: string;
}

export interface ScanStatusResponse extends ApiResponse {
  requestId: string;
  status: ScanStatus;
}

export interface ScanReportResponse extends ApiResponse {
  status: ScanStatus;
  requestId: string;
  results?: ScanResult[];
}

// Scan-related Types
export type ScanStatus = 'pending' | 'scanning' | 'processing' | 'generating_report' | 'completed' | 'failed';

export interface VulnerabilitySummary {
  severity: 'high' | 'medium' | 'low';
  description: string;
  recommendation?: string;
}

export interface ScanResult {
  target: string;
  port: number;
  service: string;
  product: string;
  version: string;
  protocol?: string;
  state?: string;
  report?: string;
  vulnerability_summary?: VulnerabilitySummary;
  http_security?: any;
  scan_metadata?: any;
}

// Error handling
export class ApiError extends Error {
  status: number;
  data?: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Generic API request handler with error handling
 */
async function apiRequest<T>(
  endpoint: string, 
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  
  try {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new ApiError(
        data.message || 'An error occurred',
        response.status,
        data
      );
    }

    return data as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    
    // Handle network errors or JSON parsing errors
    throw new ApiError(
      error instanceof Error ? error.message : 'Network error',
      0
    );
  }
}

/**
 * Submit a new scan request
 * @param websiteUrl URL to scan
 * @returns Scan request response with requestId
 */
export async function submitScan(websiteUrl: string): Promise<ScanRequestResponse> {
  return apiRequest<ScanRequestResponse>('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ website_url: websiteUrl }),
  });
}

/**
 * Get the status of a scan
 * @param requestId ID of the scan request
 * @returns Current status of the scan
 */
export async function getScanStatus(requestId: string): Promise<ScanStatusResponse> {
  return apiRequest<ScanStatusResponse>(`/api/scan-status/${requestId}`);
}

/**
 * Get the report for a completed scan
 * @param requestId ID of the scan request
 * @returns Scan report if completed, or status information
 */
export async function getScanReport(requestId: string): Promise<ScanReportResponse> {
  return apiRequest<ScanReportResponse>(`/api/report/${requestId}`);
}

/**
 * Retry a failed scan
 * @param requestId ID of the failed scan request
 * @returns Response with new requestId
 */
export async function retryScan(requestId: string): Promise<ScanRequestResponse> {
  return apiRequest<ScanRequestResponse>(`/api/retry-scan/${requestId}`, {
    method: 'POST',
  });
}

/**
 * Generate a downloadable file name for a report
 * @param requestId Scan request ID
 * @param target Target URL/domain
 * @returns Formatted filename
 */
export function generateReportFilename(requestId: string, target: string): string {
  const date = new Date().toISOString().split('T')[0];
  const sanitizedTarget = target.replace(/[^a-z0-9]/gi, '-').toLowerCase();
  return `netsage-report-${sanitizedTarget}-${date}-${requestId.substring(0, 8)}`;
}
