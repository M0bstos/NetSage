"use client"

import { useState, useEffect } from "react"
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"

export type ToastType = "success" | "error" | "info" | "warning"

export interface Toast {
  id: string
  type: ToastType
  title: string
  description?: string
  duration?: number
}

interface ToastContainerProps {
  toasts: Toast[]
  onClose: (id: string) => void
}

interface ToastNotificationProps {
  toast: Toast
  onClose: (id: string) => void
}

export function ToastNotification({ toast, onClose }: ToastNotificationProps) {
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(false)
      setTimeout(() => onClose(toast.id), 300)
    }, toast.duration || 5000)

    return () => clearTimeout(timer)
  }, [toast.id, toast.duration, onClose])

  const getToastConfig = (type: ToastType) => {
    switch (type) {
      case "success":
        return {
          icon: <CheckCircle className="h-5 w-5 text-green-400" />,
          className: "border-green-800/50 bg-green-950/40",
        }
      case "error":
        return {
          icon: <AlertCircle className="h-5 w-5 text-red-400" />,
          className: "border-red-800/50 bg-red-950/40",
        }
      case "warning":
        return {
          icon: <AlertTriangle className="h-5 w-5 text-yellow-400" />,
          className: "border-yellow-800/50 bg-yellow-950/40",
        }
      case "info":
      default:
        return {
          icon: <Info className="h-5 w-5 text-blue-400" />,
          className: "border-blue-800/50 bg-blue-950/40",
        }
    }
  }

  const config = getToastConfig(toast.type)

  return (
    <div
      className={`
        transform transition-all duration-300 ease-in-out
        ${isVisible ? "translate-x-0 opacity-100" : "translate-x-full opacity-0"}
      `}
    >
      <div
        className={`
        border rounded-lg p-4 shadow-lg backdrop-blur-sm max-w-sm w-full
        ${config.className}
      `}
      >
        <div className="flex items-start space-x-3">
          <div className="flex-shrink-0">{config.icon}</div>
          <div className="flex-1 min-w-0">
            <h4 className="text-sm font-medium text-neutral-100 mb-1">{toast.title}</h4>
            {toast.description && <p className="text-sm text-neutral-300">{toast.description}</p>}
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => {
              setIsVisible(false)
              setTimeout(() => onClose(toast.id), 300)
            }}
            className="flex-shrink-0 h-6 w-6 text-neutral-400 hover:text-neutral-100"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}

// Toast Container Component with better positioning
export function ToastContainer({ toasts, onClose }: ToastContainerProps) {
  return (
    <div className="fixed top-32 right-6 z-40 space-y-3 max-w-sm">
      {toasts.map((toast, index) => (
        <div key={toast.id} style={{ transform: `translateY(${index * 4}px)` }}>
          <ToastNotification toast={toast} onClose={onClose} />
        </div>
      ))}
    </div>
  )
}
