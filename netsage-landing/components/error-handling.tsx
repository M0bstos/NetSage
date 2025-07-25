"use client"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertTriangle, RefreshCw, Home, MessageCircle } from "lucide-react"

interface ErrorDisplayProps {
  title: string
  message: string
  errorCode?: string
  onRetry?: () => void
  onGoHome?: () => void
  showSupport?: boolean
}

export function ErrorDisplay({ title, message, errorCode, onRetry, onGoHome, showSupport = true }: ErrorDisplayProps) {
  return (
    <Card className="bg-neutral-900/40 border-neutral-800/50 max-w-md mx-auto">
      <CardHeader className="text-center">
        <div className="w-16 h-16 bg-red-950/40 rounded-full flex items-center justify-center mx-auto mb-4">
          <AlertTriangle className="h-8 w-8 text-red-400" />
        </div>
        <CardTitle className="text-xl text-neutral-100">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-center space-y-4">
        <p className="text-neutral-400 leading-relaxed">{message}</p>

        {errorCode && (
          <div className="bg-neutral-800/50 rounded-lg p-3">
            <p className="text-sm text-neutral-500">
              Error Code: <span className="text-neutral-300 font-mono">{errorCode}</span>
            </p>
          </div>
        )}

        <div className="flex flex-col sm:flex-row gap-3 pt-4">
          {onRetry && (
            <Button
              onClick={onRetry}
              className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-600/20 transition-all duration-200 flex-1"
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Try Again
            </Button>
          )}

          {onGoHome && (
            <Button
              onClick={onGoHome}
              variant="outline"
              className="border-neutral-700 hover:bg-neutral-800/50 bg-transparent text-neutral-300 hover:text-neutral-100 transition-all duration-200 flex-1"
            >
              <Home className="mr-2 h-4 w-4" />
              Go Home
            </Button>
          )}
        </div>

        {showSupport && (
          <div className="pt-4 border-t border-neutral-800/50">
            <p className="text-sm text-neutral-500 mb-2">Need help?</p>
            <Button variant="ghost" size="sm" className="text-blue-400 hover:text-blue-300 hover:bg-blue-950/20">
              <MessageCircle className="mr-2 h-4 w-4" />
              Contact Support
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// Specific Error Components
export function ScanErrorDisplay({ onRetry, url }: { onRetry: () => void; url: string }) {
  return (
    <ErrorDisplay
      title="Scan Failed"
      message={`We encountered an error while scanning ${url}. This could be due to network issues or the website being temporarily unavailable.`}
      errorCode="SCAN_001"
      onRetry={onRetry}
      onGoHome={() => window.location.reload()}
    />
  )
}

export function NetworkErrorDisplay({ onRetry }: { onRetry: () => void }) {
  return (
    <ErrorDisplay
      title="Connection Error"
      message="Unable to connect to our scanning servers. Please check your internet connection and try again."
      errorCode="NET_001"
      onRetry={onRetry}
    />
  )
}

export function RateLimitErrorDisplay({ onGoHome }: { onGoHome: () => void }) {
  return (
    <ErrorDisplay
      title="Rate Limit Exceeded"
      message="You've reached the maximum number of scans for this session. Please wait a few minutes before trying again."
      errorCode="RATE_001"
      onGoHome={onGoHome}
      showSupport={false}
    />
  )
}
