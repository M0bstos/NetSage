"use client"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Download, Share2, RotateCcw, FileText, Mail, Link2 } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

interface ReportActionsProps {
  onDownload: (format: string) => void
  onShare: (method: string) => void
  onRetry: () => void
  reportId: string
}

export function ReportActions({ onDownload, onShare, onRetry, reportId }: ReportActionsProps) {
  return (
    <Card className="bg-neutral-900/40 border-neutral-800/50">
      <CardContent className="pt-6">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Download Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-600/20 transition-all duration-200 flex-1">
                <Download className="mr-2 h-4 w-4" />
                Download Report
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-neutral-900 border-neutral-800 text-neutral-100">
              <DropdownMenuItem onClick={() => onDownload("pdf")} className="hover:bg-neutral-800 cursor-pointer">
                <FileText className="mr-2 h-4 w-4" />
                PDF Report
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onDownload("json")} className="hover:bg-neutral-800 cursor-pointer">
                <FileText className="mr-2 h-4 w-4" />
                JSON Data
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onDownload("csv")} className="hover:bg-neutral-800 cursor-pointer">
                <FileText className="mr-2 h-4 w-4" />
                CSV Export
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Share Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="border-neutral-700 hover:bg-neutral-800/50 bg-transparent text-neutral-300 hover:text-neutral-100 transition-all duration-200 flex-1"
              >
                <Share2 className="mr-2 h-4 w-4" />
                Share
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-neutral-900 border-neutral-800 text-neutral-100">
              <DropdownMenuItem onClick={() => onShare("link")} className="hover:bg-neutral-800 cursor-pointer">
                <Link2 className="mr-2 h-4 w-4" />
                Copy Link
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onShare("email")} className="hover:bg-neutral-800 cursor-pointer">
                <Mail className="mr-2 h-4 w-4" />
                Send via Email
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Retry Button */}
          <Button
            variant="outline"
            onClick={onRetry}
            className="border-neutral-700 hover:bg-neutral-800/50 bg-transparent text-neutral-300 hover:text-neutral-100 transition-all duration-200"
          >
            <RotateCcw className="mr-2 h-4 w-4" />
            Retry Scan
          </Button>
        </div>

        {/* Report Info */}
        <div className="mt-4 pt-4 border-t border-neutral-800/50">
          <div className="flex items-center justify-between text-sm text-neutral-400">
            <span>Report ID: {reportId}</span>
            <span>Generated: {new Date().toLocaleDateString()}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
