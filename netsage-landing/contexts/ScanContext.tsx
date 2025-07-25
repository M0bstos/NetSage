"use client"

import {
  createContext,
  useContext,
  useState,
  useCallback,
  ReactNode,
  useEffect,
  useRef,
} from "react"
import {
  submitScan,
  getScanStatus,
  getScanReport,
  retryScan,
  ScanStatus,
  ScanResult,
  ApiError,
} from "@/services/api"
import { useWebSocket, useScanSubscription } from "@/contexts/WebSocketContext"

// Define scan state type
export interface ScanState {
  requestId: string | null
  url: string | null
  status: ScanStatus | null
  progress: number
  currentStep: string
  error: string | null
  results: ScanResult[] | null
}

// Define scan context type
interface ScanContextType {
  scan: ScanState
  isScanning: boolean
  isSubmitting: boolean
  hasError: boolean
  hasResults: boolean
  startScan: (url: string) => Promise<string>
  retryScan: (requestId: string) => Promise<string>
  checkStatus: (requestId: string) => Promise<ScanStatus>
  fetchReport: (requestId: string) => Promise<ScanResult[] | null>
  resetScan: () => void
}

// Create context with default values
const ScanContext = createContext<ScanContextType | undefined>(undefined)

// Scan Provider Props
interface ScanProviderProps {
  children: ReactNode
}

// Define scan update type
interface ScanUpdate {
  requestId: string
  status: ScanStatus
  message?: string
}

// Map backend scan status to UI steps
function mapStatusToStep(status: ScanStatus): string {
  switch (status) {
    case "pending":
      return "initialization"
    case "scanning":
      return "vulnerability-scan"
    case "processing":
      return "vulnerability-scan"
    case "generating_report":
      return "compliance-check"
    case "completed":
      return "report-generation"
    case "failed":
      return "error"
    default:
      return "initialization"
  }
}

// Calculate progress percentage based on status
function calculateProgress(status: ScanStatus): number {
  switch (status) {
    case "pending":
      return 5
    case "scanning":
      return 30
    case "processing":
      return 60
    case "generating_report":
      return 85
    case "completed":
      return 100
    case "failed":
      return 100
    default:
      return 0
  }
}

// Scan Provider Component
export function ScanProvider({ children }: ScanProviderProps) {
  // Initialize scan state
  const [scan, setScan] = useState<ScanState>({
    requestId: null,
    url: null,
    status: null,
    progress: 0,
    currentStep: "initialization",
    error: null,
    results: null,
  })
  
  // Track submission state
  const [isSubmitting, setIsSubmitting] = useState(false)
  
  // Get WebSocket status
  const { status: wsStatus } = useWebSocket()

  // Derive additional state
  const isScanning = scan.status === "pending" || scan.status === "scanning" || scan.status === "processing" || scan.status === "generating_report"
  const hasError = scan.status === "failed" || !!scan.error
  const hasResults = scan.status === "completed" && !!scan.results
  
  // Ref for fetchReport function to avoid circular dependencies
  const fetchReportRef = useRef<(requestId: string) => Promise<ScanResult[] | null>>(null!)

  // Fetch scan report function
  const fetchReport = useCallback(async (requestId: string): Promise<ScanResult[] | null> => {
    try {
      // Get report from API
      const response = await getScanReport(requestId)
      
      // Update scan state with response
      setScan((prev) => ({
        ...prev,
        status: response.status,
        results: response.results || null,
        progress: calculateProgress(response.status),
      }))
      
      return response.results || null
    } catch (error) {
      // Handle errors
      console.error("Error fetching scan report:", error)
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : "Failed to fetch scan report"
      
      setScan((prev) => ({
        ...prev,
        error: errorMessage,
      }))
      
      return null
    }
  }, [])

  // Assign fetchReport to ref for use in useCallback dependencies
  fetchReportRef.current = fetchReport
  
  // Handle WebSocket updates for the current scan
  const handleScanUpdate = useCallback((data: ScanUpdate) => {
    console.log("Received scan update:", data)
    
    if (data.requestId !== scan.requestId) return
    
    setScan((prev) => ({
      ...prev,
      status: data.status,
      progress: calculateProgress(data.status),
      currentStep: mapStatusToStep(data.status),
      error: data.status === "failed" ? data.message || "Scan failed to complete" : null,
    }))
    
    // If scan is completed, fetch the report
    if (data.status === "completed") {
      fetchReportRef.current(data.requestId)
    }
  }, [scan.requestId])
  
  // Handle subscription to scan updates with proper dependencies
  const scanRequestId = scan.requestId; // Extract to avoid closure issues
  
  useEffect(() => {
    if (!scanRequestId) return;
    
    const handleScanEvent = (data: any) => {
      // Update the state only if it's for our current scan
      if (data.requestId === scanRequestId) {
        setScan((prev) => ({
          ...prev,
          status: data.status,
          progress: calculateProgress(data.status),
          currentStep: mapStatusToStep(data.status),
          error: data.status === "failed" ? data.message || "Scan failed to complete" : null,
        }));
        
        // If scan is completed, fetch the report
        if (data.status === "completed") {
          fetchReportRef.current(data.requestId);
        }
      }
    };
    
    // Create a subscription and get cleanup function
    const unsubscribe = useScanSubscription(scanRequestId, handleScanEvent);
    
    // Return cleanup function
    return unsubscribe;
  }, [scanRequestId])

  // Start a new scan
  const startScan = useCallback(async (url: string): Promise<string> => {
    try {
      setIsSubmitting(true)
      
      // Reset scan state
      setScan({
        requestId: null,
        url,
        status: null,
        progress: 0,
        currentStep: "initialization",
        error: null,
        results: null,
      })
      
      // Submit scan request to API
      const response = await submitScan(url)
      
      // Update scan state with response
      setScan((prev) => ({
        ...prev,
        requestId: response.requestId,
        status: "pending",
        progress: 5,
      }))
      
      return response.requestId
    } catch (error) {
      // Handle errors
      console.error("Error submitting scan:", error)
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : "Failed to submit scan request"
      
      setScan((prev) => ({
        ...prev,
        status: "failed",
        error: errorMessage,
      }))
      
      throw error
    } finally {
      setIsSubmitting(false)
    }
  }, [])

  // Retry a failed scan
  const retryScanById = useCallback(async (requestId: string): Promise<string> => {
    try {
      setIsSubmitting(true)
      
      // Submit retry request to API
      const response = await retryScan(requestId)
      
      // Update scan state with response
      setScan((prev) => ({
        ...prev,
        requestId: response.requestId,
        status: "pending",
        progress: 5,
        currentStep: "initialization",
        error: null,
        results: null,
      }))
      
      return response.requestId
    } catch (error) {
      // Handle errors
      console.error("Error retrying scan:", error)
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : "Failed to retry scan"
      
      setScan((prev) => ({
        ...prev,
        error: errorMessage,
      }))
      
      throw error
    } finally {
      setIsSubmitting(false)
    }
  }, [])

  // Check scan status
  const checkStatus = useCallback(async (requestId: string): Promise<ScanStatus> => {
    try {
      // Get status from API
      const response = await getScanStatus(requestId)
      
      // Update scan state with response
      setScan((prev) => ({
        ...prev,
        status: response.status,
        progress: calculateProgress(response.status),
        currentStep: mapStatusToStep(response.status),
      }))
      
      return response.status
    } catch (error) {
      // Handle errors
      console.error("Error checking scan status:", error)
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : "Failed to check scan status"
      
      setScan((prev) => ({
        ...prev,
        error: errorMessage,
      }))
      
      throw error
    }
  }, [])

  // Reset scan state
  const resetScan = useCallback(() => {
    setScan({
      requestId: null,
      url: null,
      status: null,
      progress: 0,
      currentStep: "initialization",
      error: null,
      results: null,
    })
  }, [])

  // Periodically check status for non-terminal states when WebSocket fails
  useEffect(() => {
    // Only check status if WebSocket is not connected and we have an ongoing scan
    if (wsStatus !== "connected" && scan.requestId && isScanning) {
      const intervalId = setInterval(() => {
        checkStatus(scan.requestId!)
          .then((status) => {
            // If scan reached terminal state, clear interval
            if (status === "completed" || status === "failed") {
              clearInterval(intervalId)
            }
          })
          .catch(() => {
            // Clear interval on error
            clearInterval(intervalId)
          })
      }, 5000) // Check every 5 seconds
      
      return () => clearInterval(intervalId)
    }
  }, [wsStatus, scan.requestId, isScanning, checkStatus])

  // Context value
  const value: ScanContextType = {
    scan,
    isScanning,
    isSubmitting,
    hasError,
    hasResults,
    startScan,
    retryScan: retryScanById,
    checkStatus,
    fetchReport,
    resetScan,
  }

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>
}

// Hook for using the Scan context
export function useScan() {
  const context = useContext(ScanContext)
  if (context === undefined) {
    throw new Error("useScan must be used within a ScanProvider")
  }
  return context
}
