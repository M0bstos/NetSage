"use client"

import { useState, useEffect } from "react"
import { Badge } from "@/components/ui/badge"
import { Wifi, WifiOff, AlertCircle } from "lucide-react"

type ConnectionStatus = "connected" | "disconnected" | "connecting" | "error"

interface WebSocketStatusProps {
  status?: ConnectionStatus
  className?: string
}

export function WebSocketStatus({ status = "connected", className = "" }: WebSocketStatusProps) {
  const [currentStatus, setCurrentStatus] = useState<ConnectionStatus>(status)

  useEffect(() => {
    setCurrentStatus(status)
  }, [status])

  const getStatusConfig = (status: ConnectionStatus) => {
    switch (status) {
      case "connected":
        return {
          icon: <Wifi className="h-3 w-3" />,
          text: "Connected",
          className: "bg-green-950/40 text-green-300 border-green-800/50",
        }
      case "connecting":
        return {
          icon: <Wifi className="h-3 w-3 animate-pulse" />,
          text: "Connecting",
          className: "bg-yellow-950/40 text-yellow-300 border-yellow-800/50",
        }
      case "error":
        return {
          icon: <AlertCircle className="h-3 w-3" />,
          text: "Error",
          className: "bg-red-950/40 text-red-300 border-red-800/50",
        }
      case "disconnected":
      default:
        return {
          icon: <WifiOff className="h-3 w-3" />,
          text: "Disconnected",
          className: "bg-neutral-800/50 text-neutral-400 border-neutral-700/50",
        }
    }
  }

  const config = getStatusConfig(currentStatus)

  return (
    <div className={`fixed top-20 right-6 z-30 ${className}`}>
      <Badge
        variant="secondary"
        className={`${config.className} flex items-center space-x-1.5 px-3 py-1.5 backdrop-blur-sm shadow-lg border`}
      >
        {config.icon}
        <span className="text-xs font-medium">{config.text}</span>
      </Badge>
    </div>
  )
}
