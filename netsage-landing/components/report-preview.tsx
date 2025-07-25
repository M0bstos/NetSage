"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AlertTriangle, CheckCircle, XCircle, Shield, FileText, Clock } from "lucide-react"

interface Vulnerability {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low"
  description: string
  affected: string
  recommendation: string
}

interface ComplianceCheck {
  standard: string
  status: "passed" | "failed" | "warning"
  score: number
  details: string
}

interface ScanResult {
  url: string
  scanDate: string
  overallScore: number
  vulnerabilities: Vulnerability[]
  compliance: ComplianceCheck[]
  scanDuration: string
}

interface ReportPreviewProps {
  result: ScanResult
}

export function ReportPreview({ result }: ReportPreviewProps) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-950/40 text-red-300 border-red-800/50"
      case "high":
        return "bg-orange-950/40 text-orange-300 border-orange-800/50"
      case "medium":
        return "bg-yellow-950/40 text-yellow-300 border-yellow-800/50"
      case "low":
        return "bg-green-950/40 text-green-300 border-green-800/50"
      default:
        return "bg-neutral-950/40 text-neutral-300 border-neutral-800/50"
    }
  }

  const getComplianceIcon = (status: string) => {
    switch (status) {
      case "passed":
        return <CheckCircle className="h-4 w-4 text-green-400" />
      case "failed":
        return <XCircle className="h-4 w-4 text-red-400" />
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-yellow-400" />
      default:
        return <Shield className="h-4 w-4 text-neutral-400" />
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400"
    if (score >= 60) return "text-yellow-400"
    if (score >= 40) return "text-orange-400"
    return "text-red-400"
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-neutral-900/40 border-neutral-800/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-xl text-neutral-100">Security Scan Report</CardTitle>
              <p className="text-neutral-400 mt-1">{result.url}</p>
            </div>
            <div className="text-right">
              <div className={`text-3xl font-bold ${getScoreColor(result.overallScore)}`}>
                {result.overallScore}/100
              </div>
              <p className="text-sm text-neutral-400">Security Score</p>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-lg font-semibold text-neutral-100">
                {result.vulnerabilities.filter((v) => v.severity === "critical").length}
              </div>
              <p className="text-sm text-red-400">Critical</p>
            </div>
            <div>
              <div className="text-lg font-semibold text-neutral-100">
                {result.vulnerabilities.filter((v) => v.severity === "high").length}
              </div>
              <p className="text-sm text-orange-400">High</p>
            </div>
            <div>
              <div className="text-lg font-semibold text-neutral-100">
                {result.vulnerabilities.filter((v) => v.severity === "medium").length}
              </div>
              <p className="text-sm text-yellow-400">Medium</p>
            </div>
            <div>
              <div className="text-lg font-semibold text-neutral-100">
                {result.vulnerabilities.filter((v) => v.severity === "low").length}
              </div>
              <p className="text-sm text-green-400">Low</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities */}
      <Card className="bg-neutral-900/40 border-neutral-800/50">
        <CardHeader>
          <CardTitle className="flex items-center text-neutral-100">
            <AlertTriangle className="h-5 w-5 mr-2 text-yellow-400" />
            Vulnerabilities Found ({result.vulnerabilities.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {result.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="border border-neutral-800/50 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-medium text-neutral-100">{vuln.title}</h4>
                  <Badge variant="secondary" className={getSeverityColor(vuln.severity)}>
                    {vuln.severity.toUpperCase()}
                  </Badge>
                </div>
                <p className="text-sm text-neutral-400 mb-2">{vuln.description}</p>
                <div className="text-xs text-neutral-500 mb-2">
                  <span className="font-medium">Affected:</span> {vuln.affected}
                </div>
                <div className="bg-blue-950/20 border border-blue-800/30 rounded p-2">
                  <p className="text-xs text-blue-300">
                    <span className="font-medium">Recommendation:</span> {vuln.recommendation}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Compliance */}
      <Card className="bg-neutral-900/40 border-neutral-800/50">
        <CardHeader>
          <CardTitle className="flex items-center text-neutral-100">
            <Shield className="h-5 w-5 mr-2 text-blue-400" />
            Compliance Checks
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {result.compliance.map((check, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 border border-neutral-800/50 rounded-lg"
              >
                <div className="flex items-center space-x-3">
                  {getComplianceIcon(check.status)}
                  <div>
                    <h4 className="font-medium text-neutral-100">{check.standard}</h4>
                    <p className="text-sm text-neutral-400">{check.details}</p>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`font-semibold ${getScoreColor(check.score)}`}>{check.score}%</div>
                  <Badge
                    variant="secondary"
                    className={
                      check.status === "passed"
                        ? "bg-green-950/40 text-green-300 border-green-800/50"
                        : check.status === "failed"
                          ? "bg-red-950/40 text-red-300 border-red-800/50"
                          : "bg-yellow-950/40 text-yellow-300 border-yellow-800/50"
                    }
                  >
                    {check.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Scan Details */}
      <Card className="bg-neutral-900/40 border-neutral-800/50">
        <CardContent className="pt-6">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="flex items-center space-x-2">
              <Clock className="h-4 w-4 text-neutral-400" />
              <span className="text-neutral-400">Scan Duration:</span>
              <span className="text-neutral-100">{result.scanDuration}</span>
            </div>
            <div className="flex items-center space-x-2">
              <FileText className="h-4 w-4 text-neutral-400" />
              <span className="text-neutral-400">Scan Date:</span>
              <span className="text-neutral-100">{result.scanDate}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
