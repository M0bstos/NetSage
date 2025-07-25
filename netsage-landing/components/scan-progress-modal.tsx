"use client"

import type React from "react"

import { useState } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { CheckCircle, Clock, AlertCircle, X, Shield, Search, FileText } from "lucide-react"

interface ScanStep {
  id: string
  title: string
  description: string
  status: "pending" | "running" | "completed" | "error"
  icon: React.ReactNode
}

interface ScanProgressModalProps {
  isOpen: boolean
  onClose: () => void
  progress: number
  currentStep: string
  url: string
}

export function ScanProgressModal({ isOpen, onClose, progress, currentStep, url }: ScanProgressModalProps) {
  const [steps] = useState<ScanStep[]>([
    {
      id: "initialization",
      title: "Initializing Scan",
      description: "Preparing security analysis for your website",
      status: progress > 0 ? "completed" : "pending",
      icon: <Shield className="h-5 w-5" />,
    },
    {
      id: "vulnerability-scan",
      title: "Vulnerability Detection",
      description: "Scanning for security vulnerabilities and threats",
      status: progress > 25 ? "completed" : currentStep === "vulnerability-scan" ? "running" : "pending",
      icon: <Search className="h-5 w-5" />,
    },
    {
      id: "compliance-check",
      title: "Compliance Analysis",
      description: "Checking compliance with security standards",
      status: progress > 60 ? "completed" : currentStep === "compliance-check" ? "running" : "pending",
      icon: <CheckCircle className="h-5 w-5" />,
    },
    {
      id: "report-generation",
      title: "Generating Report",
      description: "Compiling detailed security report",
      status: progress > 90 ? "completed" : currentStep === "report-generation" ? "running" : "pending",
      icon: <FileText className="h-5 w-5" />,
    },
  ])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-5 w-5 text-blue-400" />
      case "running":
        return <Clock className="h-5 w-5 text-blue-400 animate-spin" />
      case "error":
        return <AlertCircle className="h-5 w-5 text-red-400" />
      default:
        return <div className="h-5 w-5 rounded-full border-2 border-neutral-600" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "text-blue-400"
      case "running":
        return "text-blue-400"
      case "error":
        return "text-red-400"
      default:
        return "text-neutral-500"
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-neutral-900 border-neutral-800 text-neutral-100 max-w-md">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <DialogTitle className="text-xl font-semibold">Scanning Website</DialogTitle>
            <Button variant="ghost" size="icon" onClick={onClose} className="text-neutral-400 hover:text-neutral-100">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </DialogHeader>

        <div className="space-y-6">
          {/* URL Display */}
          <div className="bg-neutral-800/50 rounded-lg p-3">
            <p className="text-sm text-neutral-400 mb-1">Scanning URL:</p>
            <p className="text-neutral-100 font-medium truncate">{url}</p>
          </div>

          {/* Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-neutral-400">Progress</span>
              <span className="text-blue-400 font-medium">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2 bg-neutral-800">
              <div
                className="h-full bg-gradient-to-r from-blue-600 to-cyan-600 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </Progress>
          </div>

          {/* Scan Steps */}
          <div className="space-y-4">
            {steps.map((step, index) => (
              <div key={step.id} className="flex items-start space-x-3">
                <div className="flex-shrink-0 mt-0.5">{getStatusIcon(step.status)}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2">
                    <h4 className={`font-medium ${getStatusColor(step.status)}`}>{step.title}</h4>
                    {step.status === "running" && (
                      <Badge variant="secondary" className="bg-blue-950/40 text-blue-300 border-blue-800/50 text-xs">
                        Running
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-neutral-400 mt-1">{step.description}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Estimated Time */}
          <div className="bg-neutral-800/30 rounded-lg p-3 text-center">
            <p className="text-sm text-neutral-400">
              Estimated time remaining:{" "}
              <span className="text-neutral-100 font-medium">
                {progress < 25
                  ? "45-60 seconds"
                  : progress < 60
                    ? "30-45 seconds"
                    : progress < 90
                      ? "15-30 seconds"
                      : "5-10 seconds"}
              </span>
            </p>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
