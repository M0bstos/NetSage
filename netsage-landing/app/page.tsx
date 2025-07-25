"use client"

import type React from "react"

import { useState, useMemo, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Shield, Search, FileText, CheckCircle, Globe, Menu, ArrowRight, Clock, X } from "lucide-react"
import Image from "next/image"
import { toast } from "sonner"

// Import our custom components
import { ScanProgressModal } from "@/components/scan-progress-modal"
import { ReportPreview } from "@/components/report-preview"
import { ReportActions } from "@/components/report-actions"
import { WebSocketStatus } from "@/components/websocket-status"

// Import contexts
import { useWebSocket } from "@/contexts/WebSocketContext"
import { useScan } from "@/contexts/ScanContext"

// Define helper types for the report view
type VulnerabilityItem = {
  id: string;
  title: string;
  severity: "high" | "medium" | "low";
  description: string;
  affected: string;
  recommendation: string;
}

type ComplianceItem = {
  standard: string;
  status: "passed" | "failed" | "warning";
  score: number;
  details: string;
}

type ReportData = {
  url: string;
  scanDate: string;
  overallScore: number;
  scanDuration: string;
  vulnerabilities: VulnerabilityItem[];
  compliance: ComplianceItem[];
}

export default function HomePage() {
  // Form state
  const [urlInput, setUrlInput] = useState("")
  const [showReportModal, setShowReportModal] = useState(false)
  
  // Get WebSocket context
  const { status: wsStatus } = useWebSocket()
  
  // Get scan context
  const {
    scan,
    isSubmitting,
    isScanning,
    hasResults,
    hasError,
    startScan,
    retryScan,
    resetScan,
    fetchReport,
  } = useScan()

  // URL validation
  const isValidUrl = (url: string) => {
    try {
      const urlObj = new URL(url.startsWith("http") ? url : `https://${url}`)
      return urlObj.protocol === "http:" || urlObj.protocol === "https:"
    } catch {
      return false
    }
  }

  // Form submission handler
  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!urlInput.trim()) {
      toast.error("Please enter a website URL to scan.", {
        description: "URL Required",
      })
      return
    }

    if (!isValidUrl(urlInput)) {
      toast.error("Please enter a valid website URL (e.g., example.com).", {
        description: "Invalid URL",
      })
      return
    }

    try {
      // Start scan process with real API
      const formattedUrl = urlInput.startsWith("http") ? urlInput : `https://${urlInput}`
      await startScan(formattedUrl)
      
      toast.info(`Security scan initiated for ${urlInput}`, {
        description: "Scan Started",
      })
      
    } catch (error) {
      toast.error("Failed to start scan. Please try again later.", {
        description: error instanceof Error ? error.message : "Unknown error",
      })
    }
  }

  // Report action handlers
  const handleDownload = (format: string) => {
    if (!scan.requestId || !scan.results) return
    
    toast.info(`Preparing ${format.toUpperCase()} report for download.`, {
      description: "Download Started",
    })

    try {
      // Here we would implement the actual file download
      // For now, simulate it with a timeout
      setTimeout(() => {
        toast.success(`${format.toUpperCase()} report has been downloaded.`, {
          description: "Download Complete",
        })
      }, 2000)
    } catch (error) {
      toast.error("Failed to download report.", {
        description: error instanceof Error ? error.message : "Unknown error",
      })
    }
  }

  const handleShare = (method: string) => {
    if (!scan.requestId) return
    
    try {
      if (method === "link") {
        // Generate and copy share link
        const shareLink = `${window.location.origin}/report/${scan.requestId}`
        navigator.clipboard.writeText(shareLink)
      }
      
      toast.success(`Report ${method === "link" ? "link copied to clipboard" : "sent via email"}.`, {
        description: "Shared Successfully",
      })
    } catch (error) {
      toast.error(`Failed to share report via ${method}.`, {
        description: error instanceof Error ? error.message : "Unknown error",
      })
    }
  }

  const handleRetry = async () => {
    if (!scan.requestId) return
    
    try {
      setShowReportModal(false)
      await retryScan(scan.requestId)
      
      toast.info("Retrying scan...", {
        description: `Rescanning ${scan.url || "website"}`,
      })
    } catch (error) {
      toast.error("Failed to retry scan. Please try again later.", {
        description: error instanceof Error ? error.message : "Unknown error", 
      })
    }
  }

  // Effect to show report modal when results are ready
  useEffect(() => {
    if (scan.status === "completed" && scan.results) {
      setShowReportModal(true)
    }
  }, [scan.status, scan.results])
  
  // Update the modal visibility based on scan status
  const handleReportModalChange = (isOpen: boolean) => {
    setShowReportModal(isOpen)
  }
  
  // Transform backend scan results to the format expected by ReportPreview component
  const formattedReportData = useMemo<ReportData | null>(() => {
    if (!scan.results) return null
    
    // Calculate an overall score based on the number of issues found
    const calculateScore = () => {
      // Simple scoring mechanism for demo purposes
      return Math.max(30, Math.min(95, 100 - (scan.results?.length || 0) * 5))
    }
    
    return {
      url: scan.url || "Unknown URL",
      scanDate: new Date().toLocaleDateString(),
      overallScore: calculateScore(),
      scanDuration: "Completed",
      vulnerabilities: scan.results.map(result => ({
        id: result.port.toString(),
        title: `${result.service} ${result.product || ""} ${result.version || ""}`.trim(),
        severity: result.report.includes("high") ? "high" : 
                 result.report.includes("medium") ? "medium" : "low",
        description: result.report,
        affected: `${result.target}:${result.port}`,
        recommendation: "Update service to latest version and apply security patches."
      })),
      compliance: [
        {
          standard: "Security Best Practices",
          status: calculateScore() > 70 ? "passed" : "warning",
          score: calculateScore(),
          details: "Assessment based on discovered security vulnerabilities."
        }
      ]
    }
  }, [scan.results, scan.url])

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      {/* Header */}
      <header className="border-b border-neutral-800/40 backdrop-blur-sm sticky top-0 z-50 bg-neutral-950/90">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
              <span className="text-2xl font-bold text-neutral-100">NetSage</span>
            </div>
            <nav className="hidden md:flex items-center space-x-8">
              <a href="#features" className="text-neutral-400 hover:text-neutral-100 transition-colors duration-200">
                Features
              </a>
              <a
                href="#how-it-works"
                className="text-neutral-400 hover:text-neutral-100 transition-colors duration-200"
              >
                How it works
              </a>
              <Button
                onClick={() => document.getElementById("scan-form")?.scrollIntoView({ behavior: "smooth" })}
                className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-600/20 transition-all duration-200"
              >
                Start Scan
              </Button>
            </nav>
            <Button variant="ghost" size="icon" className="md:hidden text-neutral-400 hover:text-neutral-100">
              <Menu className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      {/* WebSocket Status Indicator - positioned after header */}
      <WebSocketStatus status={wsStatus} />

      {/* Hero Section with Integrated Scan Form */}
      <section className="py-20 lg:py-28 px-6">
        <div className="container mx-auto">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div className="space-y-8">
              <Badge variant="secondary" className="bg-blue-950/40 text-blue-300 border-blue-800/50 px-4 py-2">
                <Shield className="w-4 h-4 mr-2" />
                WEBSITE SECURITY
              </Badge>
              <h1 className="text-4xl lg:text-5xl xl:text-6xl font-bold leading-tight text-neutral-100">
                Effortless security insights for your{" "}
                <span className="text-transparent bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text">
                  website
                </span>
              </h1>
              <p className="text-lg lg:text-xl text-neutral-400 leading-relaxed max-w-xl">
                Quickly scan your site for vulnerabilities and get detailed reports. Easy to use, with results you can
                download in any format.
              </p>

              {/* Integrated Scan Form */}
              <div id="scan-form" className="bg-neutral-900/50 border border-neutral-800/50 rounded-2xl p-6 space-y-4">
                <h3 className="text-xl font-semibold text-neutral-100 mb-4">Start Your Security Scan</h3>
                <form onSubmit={handleScanSubmit} className="space-y-4">
                  <div className="flex flex-col sm:flex-row gap-3">
                    <Input
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Enter website URL (e.g., example.com)"
                      className="flex-1 bg-neutral-800/50 border-neutral-700 text-neutral-100 placeholder-neutral-400 focus:border-blue-500"
                      disabled={isSubmitting || isScanning}
                    />
                    <Button
                      type="submit"
                      disabled={isSubmitting || isScanning}
                      className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-600/20 transition-all duration-200 disabled:opacity-50"
                    >
                      {isSubmitting ? (
                        <>
                          <Clock className="mr-2 h-4 w-4 animate-spin" />
                          Starting...
                        </>
                      ) : isScanning ? (
                        <>
                          <Clock className="mr-2 h-4 w-4 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Search className="mr-2 h-4 w-4" />
                          Scan Now
                        </>
                      )}
                    </Button>
                  </div>
                  <p className="text-sm text-neutral-500">
                    {hasError ? (
                      <span className="text-red-400">Error: {scan.error}</span>
                    ) : (
                      "Free scan • No registration required • Results in 60 seconds"
                    )}
                  </p>
                </form>
              </div>

              <div className="flex items-center space-x-8 pt-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">50K+</div>
                  <div className="text-sm text-neutral-500">Sites Scanned</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">99.9%</div>
                  <div className="text-sm text-neutral-500">Accuracy</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">24/7</div>
                  <div className="text-sm text-neutral-500">Available</div>
                </div>
              </div>
            </div>

            {/* Hero Image */}
            <div className="relative">
              <div className="relative overflow-hidden rounded-2xl bg-neutral-900/50 border border-neutral-800/50">
                <Image
                  src="/placeholder.svg?height=500&width=600&text=Security+Dashboard"
                  alt="NetSage Security Dashboard"
                  width={600}
                  height={500}
                  className="w-full h-[500px] object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-neutral-900/40 to-transparent"></div>
              </div>
              <div className="absolute -inset-4 bg-gradient-to-r from-blue-600/10 to-cyan-600/10 rounded-3xl blur-xl -z-10"></div>
            </div>
          </div>
        </div>
      </section>

      {/* Rest of the existing sections remain the same */}
      {/* Key Features Section */}
      <section id="features" className="py-20 lg:py-28 px-6 bg-neutral-900/30">
        <div className="container mx-auto">
          <div className="text-center max-w-4xl mx-auto mb-16">
            <Badge variant="secondary" className="bg-blue-950/40 text-blue-300 border-blue-800/50 mb-6">
              KEY FEATURES
            </Badge>
            <h2 className="text-3xl lg:text-4xl font-bold mb-6 text-neutral-100">Simple security solutions</h2>
            <p className="text-lg lg:text-xl text-neutral-400 mb-10 leading-relaxed">
              Secure your site effortlessly. Just enter your domain, hit scan, and let us handle the rest.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            {/* Feature Card 1 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <FileText className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-semibold mb-4 text-neutral-100">Detailed Reports</h3>
                <p className="text-neutral-400 leading-relaxed flex-grow">
                  Comprehensive security reports with clear explanations, risk assessments, and step-by-step remediation
                  guides for every vulnerability found.
                </p>
              </CardContent>
            </Card>

            {/* Feature Card 2 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <CheckCircle className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-semibold mb-4 text-neutral-100">Compliance Checking</h3>
                <p className="text-neutral-400 leading-relaxed flex-grow">
                  Ensure your website meets industry standards and compliance requirements including GDPR, PCI DSS, and
                  other security frameworks.
                </p>
              </CardContent>
            </Card>

            {/* Feature Card 3 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <Globe className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-semibold mb-4 text-neutral-100">Multi-Domain Support</h3>
                <p className="text-neutral-400 leading-relaxed flex-grow">
                  Scan multiple websites and domains from a single interface. Perfect for agencies and businesses with
                  multiple web properties.
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Feature Image */}
          <div className="mt-16 relative rounded-2xl overflow-hidden bg-neutral-900/50 border border-neutral-800/50">
            <Image
              src="/placeholder.svg?height=400&width=1200&text=NetSage+Security+Reports"
              alt="NetSage Security Reports Dashboard"
              width={1200}
              height={400}
              className="w-full h-[400px] object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-neutral-950/60 via-transparent to-transparent"></div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-20 lg:py-28 px-6">
        <div className="container mx-auto">
          <div className="text-center mb-16">
            <Badge variant="secondary" className="bg-blue-950/40 text-blue-300 border-blue-800/50 mb-6">
              HOW IT WORKS
            </Badge>
            <h2 className="text-3xl lg:text-4xl font-bold mb-6 text-neutral-100">Three simple steps to security</h2>
            <p className="text-lg text-neutral-400 max-w-3xl mx-auto leading-relaxed">
              Our streamlined process makes website security accessible and manageable for everyone.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {/* Step 1 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <Search className="h-8 w-8 text-white" />
                </div>
                <div className="flex items-center mb-4">
                  <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold text-sm mr-3">
                    1
                  </div>
                  <h3 className="text-xl font-semibold text-neutral-100">Enter Your URL</h3>
                </div>
                <p className="text-neutral-400 mb-6 leading-relaxed flex-grow">
                  Simply enter your website URL in the scan form. Our system supports all major website platforms and
                  technologies.
                </p>
              </CardContent>
            </Card>

            {/* Step 2 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <Clock className="h-8 w-8 text-white" />
                </div>
                <div className="flex items-center mb-4">
                  <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold text-sm mr-3">
                    2
                  </div>
                  <h3 className="text-xl font-semibold text-neutral-100">Automated Scanning</h3>
                </div>
                <p className="text-neutral-400 mb-6 leading-relaxed flex-grow">
                  Our advanced scanning engine performs comprehensive security checks including vulnerability detection
                  and compliance validation.
                </p>
              </CardContent>
            </Card>

            {/* Step 3 */}
            <Card className="bg-neutral-900/40 border-neutral-800/50 p-8 hover:bg-neutral-900/60 transition-all duration-300 group h-full">
              <CardContent className="p-0 flex flex-col h-full">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl flex items-center justify-center mb-6 group-hover:scale-105 transition-transform duration-200">
                  <FileText className="h-8 w-8 text-white" />
                </div>
                <div className="flex items-center mb-4">
                  <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold text-sm mr-3">
                    3
                  </div>
                  <h3 className="text-xl font-semibold text-neutral-100">Get Your Report</h3>
                </div>
                <p className="text-neutral-400 mb-6 leading-relaxed flex-grow">
                  Receive a comprehensive security report with prioritized recommendations and compliance status. Export
                  in multiple formats.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 lg:py-28 px-6 bg-gradient-to-br from-blue-950/20 via-neutral-900/30 to-cyan-950/20">
        <div className="container mx-auto text-center">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-3xl lg:text-4xl font-bold mb-6 text-neutral-100">Ready to secure your website?</h2>
            <p className="text-lg lg:text-xl text-neutral-400 mb-10 leading-relaxed">
              Start your free security scan today and get instant insights into your website's vulnerabilities and
              compliance status.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
              <Button
                onClick={() => document.getElementById("scan-form")?.scrollIntoView({ behavior: "smooth" })}
                size="lg"
                className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-600/20 transition-all duration-200"
              >
                <Shield className="mr-2 h-5 w-5" />
                Start Free Scan
              </Button>
              <Button
                size="lg"
                variant="outline"
                className="border-neutral-700 hover:bg-neutral-800/50 bg-transparent text-neutral-300 hover:text-neutral-100 transition-all duration-200"
              >
                View Demo
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
            <div className="flex items-center justify-center space-x-6 text-sm text-neutral-500">
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 mr-2 text-blue-400" />
                No registration required
              </div>
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 mr-2 text-blue-400" />
                Free to use
              </div>
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 mr-2 text-blue-400" />
                Instant results
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-neutral-800/40 py-12 px-6 bg-neutral-900/20">
        <div className="container mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center space-x-3 mb-4 md:mb-0">
              <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
              <span className="text-xl font-bold text-neutral-100">NetSage</span>
            </div>
            <p className="text-neutral-500 text-center md:text-right">
              &copy; 2024 NetSage. Effortless security insights for your website.
            </p>
          </div>
        </div>
      </footer>

      {/* Modals */}
      {/* Scan Progress Modal */}
      <ScanProgressModal
        isOpen={isScanning}
        onClose={() => resetScan()}
        progress={scan.progress}
        currentStep={scan.currentStep}
        url={scan.url || urlInput}
      />

      {/* Report Results Modal */}
      <Dialog open={showReportModal} onOpenChange={handleReportModalChange}>
        <DialogContent className="bg-neutral-900 border-neutral-800 text-neutral-100 max-w-4xl max-h-[90vh] overflow-y-auto z-50">
          <DialogHeader>
            <div className="flex items-center justify-between">
              <DialogTitle className="text-2xl font-bold">Security Scan Results</DialogTitle>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setShowReportModal(false)}
                className="text-neutral-400 hover:text-neutral-100"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </DialogHeader>

          {formattedReportData && (
            <div className="space-y-6">
              <ReportPreview result={formattedReportData} />
              <ReportActions
                onDownload={handleDownload}
                onShare={handleShare}
                onRetry={handleRetry}
                reportId={scan.requestId || ""}
              />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
