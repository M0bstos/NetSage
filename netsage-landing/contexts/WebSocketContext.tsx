"use client"

import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from "react"
import { io, Socket } from "socket.io-client"
import { ScanStatus } from "@/services/api"

// Define WebSocket connection states
export type ConnectionStatus = "connected" | "disconnected" | "connecting" | "error"

// Define WebSocket event data types
export interface ScanUpdateEvent {
  requestId: string
  status: ScanStatus
  previousStatus?: ScanStatus
  timestamp: string
}

export interface NotificationEvent {
  message: string
  type: "info" | "warning" | "error"
  timestamp: string
}

// Define WebSocket context interface
interface WebSocketContextType {
  socket: Socket | null
  status: ConnectionStatus
  subscribeTo: (requestId: string) => void
  unsubscribeFrom: (requestId: string) => void
  reconnect: () => void
}

// Create context with default values
const WebSocketContext = createContext<WebSocketContextType>({
  socket: null,
  status: "disconnected",
  subscribeTo: () => {},
  unsubscribeFrom: () => {},
  reconnect: () => {},
})

// WebSocket Provider Props
interface WebSocketProviderProps {
  children: ReactNode
}

// Socket URL from environment variables
const SOCKET_URL = typeof window !== 'undefined' 
  ? (process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000")
  : ""

// WebSocket Provider Component
export function WebSocketProvider({ children }: WebSocketProviderProps) {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [status, setStatus] = useState<ConnectionStatus>("disconnected")

  // Initialize socket connection
  const initializeSocket = useCallback(() => {
    try {
      // Only run on client side
      if (typeof window === 'undefined') return;
      
      // Close existing socket if any
      if (socket) {
        socket.disconnect()
      }

      setStatus("connecting")

      // Create new socket connection with client-side only
      const newSocket = io(SOCKET_URL, {
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      })

      // Set up event handlers
      newSocket.on("connect", () => {
        console.log("WebSocket connected")
        setStatus("connected")
      })

      newSocket.on("disconnect", () => {
        console.log("WebSocket disconnected")
        setStatus("disconnected")
      })

      newSocket.on("connect_error", (error) => {
        console.error("WebSocket connection error:", error)
        setStatus("error")
      })

      setSocket(newSocket)

      return () => {
        newSocket.disconnect()
      }
    } catch (error) {
      console.error("Failed to initialize WebSocket:", error)
      setStatus("error")
    }
  }, [socket])

  // Initialize connection on mount (client-side only)
  useEffect(() => {
    let cleanupFn: (() => void) | undefined;
    
    // Only run on client side
    if (typeof window !== 'undefined') {
      cleanupFn = initializeSocket();
    }
    
    return () => {
      if (cleanupFn) cleanupFn();
    };
  }, [initializeSocket])

  // Subscribe to scan updates
  const subscribeTo = useCallback(
    (requestId: string) => {
      if (socket && socket.connected) {
        console.log(`Subscribing to updates for scan ${requestId}`)
        socket.emit("subscribe", requestId)
      }
    },
    [socket]
  )

  // Unsubscribe from scan updates
  const unsubscribeFrom = useCallback(
    (requestId: string) => {
      if (socket && socket.connected) {
        console.log(`Unsubscribing from updates for scan ${requestId}`)
        socket.emit("unsubscribe", requestId)
      }
    },
    [socket]
  )

  // Reconnect to WebSocket server
  const reconnect = useCallback(() => {
    initializeSocket()
  }, [initializeSocket])

  // Context value
  const value: WebSocketContextType = {
    socket,
    status,
    subscribeTo,
    unsubscribeFrom,
    reconnect,
  }

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
}

// Hook for using the WebSocket context
export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider")
  }
  return context
}

// Hook for subscribing to scan updates
export function useScanSubscription(
  requestId: string | null,
  onUpdate?: (data: ScanUpdateEvent) => void
) {
  const { socket, subscribeTo, unsubscribeFrom } = useWebSocket()

  useEffect(() => {
    if (!requestId || !socket) return

    // Set up scan update listener - memoizing the handler to avoid frequent changes
    const handleScanUpdate = (data: ScanUpdateEvent) => {
      console.log(`Received update for scan ${data.requestId}:`, data)
      if (onUpdate && data.requestId === requestId) {
        onUpdate(data)
      }
    }

    // Subscribe to updates and listen for events
    subscribeTo(requestId)
    socket.on("scanUpdate", handleScanUpdate)

    // Cleanup on unmount or when requestId changes
    return () => {
      socket.off("scanUpdate", handleScanUpdate)
      unsubscribeFrom(requestId)
    }
  }, [requestId, socket, subscribeTo, unsubscribeFrom, onUpdate])
  
  // Return a cleanup function that can be called by consumers
  return () => {
    if (socket && requestId) {
      socket.off("scanUpdate")
      unsubscribeFrom(requestId)
    }
  }
}

// Hook for listening to system notifications
export function useSystemNotifications(
  onNotification?: (data: NotificationEvent) => void
) {
  const { socket } = useWebSocket()

  useEffect(() => {
    if (!socket) return

    // Set up notification listener
    const handleNotification = (data: NotificationEvent) => {
      console.log(`Received system notification:`, data)
      if (onNotification) onNotification(data)
    }

    // Listen for notification events
    socket.on("notification", handleNotification)

    // Cleanup on unmount
    return () => {
      socket.off("notification", handleNotification)
    }
  }, [socket, onNotification])
}
